CREATE DATABASE IF NOT EXISTS security_gateway;
USE security_gateway;

CREATE TABLE IF NOT EXISTS security_events (
    incident_id VARCHAR(36) PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    source_ip VARCHAR(45) NOT NULL,          -- Accommodates both IPv4 and IPv6 strings
    user_agent TEXT,
    target_uri VARCHAR(2048) NOT NULL,
    malicious_payload TEXT,
    threat_category ENUM('SQLi', 'XSS', 'Anomalous') NOT NULL,
    mitigation_action ENUM('Blocked', 'Flagged', 'Challenged') NOT NULL,

    -- Performance Indexing Strategy for SIEM Dashboard Performance
    INDEX idx_timestamp (timestamp),
    INDEX idx_threat_category (threat_category)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

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

CREATE TABLE IF NOT EXISTS mitigation_state (
    id VARCHAR(50) PRIMARY KEY,
    posture VARCHAR(50) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
