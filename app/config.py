import os

DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', 'your_secure_password'),
    'database': os.getenv('DB_NAME', 'security_gateway')
}

UPSTREAM_SERVER_URL = os.getenv("UPSTREAM_SERVER_URL", "http://127.0.0.1:8080")
RATE_LIMIT_THRESHOLD = 50
RATE_LIMIT_WINDOW = 10
