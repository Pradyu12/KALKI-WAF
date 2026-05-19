import mysql.connector
import sqlite3
import os
from .config import DB_CONFIG

def get_db_connection():
    """Tries to connect to MariaDB/MySQL. If it fails, falls back gracefully to SQLite in the workspace."""
    try:
        # Avoid connecting if DB_HOST is set to localhost and local port is offline
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn, "mysql"
    except Exception:
        # Fallback to local SQLite file
        conn = sqlite3.connect("security_gateway.db")
        conn.row_factory = sqlite3.Row
        return conn, "sqlite"

def query_db(query: str, args: tuple = (), one: bool = False):
    """Database query wrapper that adapts syntax between MySQL (%s) and SQLite (?)."""
    conn, db_type = get_db_connection()
    if db_type == "sqlite":
        query = query.replace("%s", "?")
    try:
        if db_type == "mysql":
            cursor = conn.cursor(dictionary=True)
            cursor.execute(query, args)
            rv = cursor.fetchall()
            cursor.close()
        else:
            cursor = conn.execute(query, args)
            rv = [dict(row) for row in cursor.fetchall()]
            cursor.close()
        return (rv[0] if rv else None) if one else rv
    except Exception as e:
        print(f"[DATABASE ERROR] Query execution failed: {e}")
        return None
    finally:
        conn.close()

def execute_db(query: str, args: tuple = ()) -> bool:
    """Database write transaction wrapper that adapts syntax between MySQL (%s) and SQLite (?)."""
    conn, db_type = get_db_connection()
    if db_type == "sqlite":
        query = query.replace("%s", "?")
    try:
        if db_type == "mysql":
            cursor = conn.cursor()
            cursor.execute(query, args)
            conn.commit()
            cursor.close()
        else:
            conn.execute(query, args)
            conn.commit()
        return True
    except Exception as e:
        print(f"[DATABASE ERROR] Write transaction failed: {e}")
        return False
    finally:
        conn.close()

def init_db():
    """Bootstraps necessary tables for alerts, rules, and global postures in MySQL or SQLite."""
    conn, db_type = get_db_connection()
    try:
        if db_type == "sqlite":
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    incident_id TEXT PRIMARY KEY,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    source_ip TEXT NOT NULL,
                    user_agent TEXT,
                    target_uri TEXT NOT NULL,
                    malicious_payload TEXT,
                    threat_category TEXT NOT NULL,
                    mitigation_action TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS rules (
                    rule_id TEXT PRIMARY KEY,
                    identifier TEXT NOT NULL UNIQUE,
                    pattern TEXT NOT NULL,
                    action TEXT NOT NULL,
                    category TEXT NOT NULL,
                    is_active INTEGER DEFAULT 1,
                    blocks_count INTEGER DEFAULT 0,
                    severity TEXT NOT NULL,
                    description TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS mitigation_state (
                    id TEXT PRIMARY KEY,
                    posture TEXT NOT NULL
                )
            """)
        else:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    incident_id VARCHAR(36) PRIMARY KEY,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    source_ip VARCHAR(45) NOT NULL,
                    user_agent TEXT,
                    target_uri VARCHAR(2048) NOT NULL,
                    malicious_payload TEXT,
                    threat_category VARCHAR(50) NOT NULL,
                    mitigation_action VARCHAR(50) NOT NULL,
                    INDEX idx_timestamp (timestamp),
                    INDEX idx_threat_category (threat_category)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS rules (
                    rule_id VARCHAR(36) PRIMARY KEY,
                    identifier VARCHAR(255) NOT NULL UNIQUE,
                    pattern TEXT NOT NULL,
                    action VARCHAR(50) NOT NULL,
                    category VARCHAR(50) NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    blocks_count INT DEFAULT 0,
                    severity VARCHAR(50) NOT NULL,
                    description TEXT
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS mitigation_state (
                    id VARCHAR(50) PRIMARY KEY,
                    posture VARCHAR(50) NOT NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)
            cursor.close()
        conn.commit()

        # Seed defaults if empty
        rules_check = query_db("SELECT COUNT(*) as cnt FROM rules", one=True)
        if rules_check and rules_check['cnt'] == 0:
            seed_rules = [
                ("sql-core-01", "OWASP SQLi Core Ruleset",
                 r"(\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|ALTER|WHERE|OR|AND)\b)|(['\x22\x2d\x23\x2a])|(\/\*[\s\S]*?\*\/)",
                 "Drop & Blacklist", "SQLi", 1, 1420, "Level 1",
                 "Comprehensive SQL Injection protection targeting all known escape vectors and UNION-based attacks."),
                ("xss-scrutiny-01", "XSS Aggressive Scrutiny",
                 r"(<script.*?>[\s\S]*?<\/script>)|(javascript\s*:\s*\S+)|(on\w+\s*=\s*['\"].*?['\"])|(<\s*iframe.*?>)",
                 "Drop & Blacklist", "XSS", 1, 92, "Level 3",
                 "High-sensitivity detection for cross-site scripting in JSON payloads and GraphQL endpoints."),
                ("bot-blocker-01", "Bad Bot Blocker [Legacy]",
                 r"(curl|wget|python-requests|scrapy|nikto|sqlmap|nmap)",
                 "Log Payload Only", "DEPRECATED", 0, 0, "DEPRECATED",
                 "Simple user-agent based bot blocking. Superseded by AEGIS AI-Fingerprinting."),
                ("rfi-blocker-01", "Remote File Inclusion (RFI)",
                 r"(https?|ftp|file|php|data):\/",
                 "Drop & Blacklist", "CRITICAL", 1, 12, "CRITICAL",
                 "Blocks attempts to include remote files via URI schemes in parameter fields.")
            ]
            for r in seed_rules:
                execute_db("""
                    INSERT INTO rules (rule_id, identifier, pattern, action, category, is_active, blocks_count, severity, description)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, r)

        posture_check = query_db("SELECT COUNT(*) as cnt FROM mitigation_state", one=True)
        if posture_check and posture_check['cnt'] == 0:
            execute_db("INSERT INTO mitigation_state (id, posture) VALUES ('global', 'Standard Posture')")

    except Exception as e:
        print(f"[CRITICAL] Database bootstrapping sequence failed: {e}")
    finally:
        conn.close()
