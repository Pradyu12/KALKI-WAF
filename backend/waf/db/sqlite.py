import os
import sqlite3
import threading

DB_PATH = os.getenv("DB_PATH", "security_gateway.db")
_BUSY_TIMEOUT = 5000
_MAX_CONNECTIONS = 10

_local = threading.local()


def _get_pool_connection():
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(DB_PATH, timeout=5.0)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT}")
        _local.conn.execute("PRAGMA foreign_keys=ON")
    return _local.conn


def get_connection():
    return _get_pool_connection()


def query_sqlite(query: str, args: tuple = (), one: bool = False):
    conn = _get_pool_connection()
    try:
        cursor = conn.execute(query, args)
        rv = [dict(row) for row in cursor.fetchall()]
        cursor.close()
        return (rv[0] if rv else None) if one else rv
    except Exception as e:
        print(f"[DATABASE ERROR] Query execution failed: {e}")
        return None


def execute_sqlite(query: str, args: tuple = ()) -> bool:
    conn = _get_pool_connection()
    try:
        conn.execute(query, args)
        conn.commit()
        return True
    except Exception as e:
        print(f"[DATABASE ERROR] Write transaction failed: {e}")
        return False


def init_sqlite_tables():
    conn = _get_pool_connection()
    try:
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
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_security_events_category
            ON security_events(threat_category)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_security_events_timestamp
            ON security_events(timestamp)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_security_events_source_ip
            ON security_events(source_ip)
        """)
        # SIEM/XDR tables
        conn.execute("""
            CREATE TABLE IF NOT EXISTS siem_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                source TEXT NOT NULL,
                description TEXT,
                raw_data TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                acked INTEGER DEFAULT 0
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_siem_alerts_ts
            ON siem_alerts(timestamp)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_siem_alerts_severity
            ON siem_alerts(severity)
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS fim_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                change_type TEXT NOT NULL,
                old_hash TEXT,
                new_hash TEXT,
                old_permissions TEXT,
                new_permissions TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_fim_events_path
            ON fim_events(file_path)
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS fim_baseline (
                file_path TEXT PRIMARY KEY,
                file_hash TEXT NOT NULL,
                permissions TEXT,
                owner TEXT,
                size INTEGER,
                last_checked DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sca_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                benchmark_id TEXT NOT NULL,
                check_id TEXT NOT NULL,
                title TEXT,
                passed INTEGER NOT NULL DEFAULT 0,
                actual_value TEXT,
                expected_value TEXT,
                severity TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sca_benchmark_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                benchmark_id TEXT NOT NULL,
                total_checks INTEGER DEFAULT 0,
                passed_checks INTEGER DEFAULT 0,
                score REAL DEFAULT 0.0,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vuln_db (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                cvss_score REAL,
                severity TEXT,
                affected_packages TEXT,
                published_date TEXT,
                last_updated TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS software_inventory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_name TEXT NOT NULL,
                package_version TEXT NOT NULL,
                package_type TEXT,
                install_path TEXT,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS active_response_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                playbook_id TEXT NOT NULL,
                action_taken TEXT NOT NULL,
                target TEXT NOT NULL,
                rule_id TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                result TEXT,
                triggered_by TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS hids_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_source TEXT NOT NULL,
                log_type TEXT NOT NULL,
                log_content TEXT,
                matched_rule TEXT,
                severity TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                acked INTEGER DEFAULT 0
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_hids_alerts_ts
            ON hids_alerts(timestamp)
        """)
        # Remote agents table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                os_info TEXT,
                ip_address TEXT,
                agent_version TEXT,
                status TEXT DEFAULT 'inactive',
                last_heartbeat DATETIME,
                registered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                tags TEXT DEFAULT '[]'
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                result_type TEXT NOT NULL,
                payload TEXT NOT NULL,
                summary TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_agent_results_agent
            ON agent_results(agent_id, timestamp)
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                command TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                delivered_at DATETIME,
                completed_at DATETIME,
                result_id INTEGER,
                FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_agent_commands_pending
            ON agent_commands(agent_id, status)
        """)
        conn.commit()
        print("[INFO] Database tables synchronized. Scheme: SQLITE")
    except Exception as e:
        print(f"[CRITICAL] Database bootstrapping sequence failed: {e}")
