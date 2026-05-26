import os

JWT_SECRET: str = os.getenv("JWT_SECRET", "")
ADMIN_API_KEY: str | None = os.getenv("ADMIN_API_KEY") or None
MAX_BODY_BYTES: int = int(os.getenv("MAX_BODY_BYTES", str(10 * 1024 * 1024)))
UPSTREAM_SERVER_URL: str = os.getenv("UPSTREAM_SERVER_URL", "http://127.0.0.1:8080")
REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")

FIREBASE_CREDENTIALS_PATH: str = os.getenv("FIREBASE_CREDENTIALS_PATH", "firebase-credentials.json")
GEOIP_DB_PATH: str = os.getenv("GEOIP_DB_PATH", "GeoLite2-Country.mmdb")
GEOIP_CITY_DB_PATH: str = os.getenv("GEOIP_CITY_DB_PATH", "GeoLite2-City.mmdb")
BLOCKED_COUNTRIES: set[str] = (
    set(os.getenv("BLOCKED_COUNTRIES", "").split(",")) if os.getenv("BLOCKED_COUNTRIES") else set()
)  # noqa: E501

GRAPHQL_MAX_DEPTH: int = int(os.getenv("GRAPHQL_MAX_DEPTH", "5"))

FIREWALL_LAT: float = float(os.getenv("FIREWALL_LAT", "37.7749"))
FIREWALL_LON: float = float(os.getenv("FIREWALL_LON", "-122.4194"))
FIREWALL_LABEL: str = os.getenv("FIREWALL_LABEL", "WAF Node")

RATE_LIMIT_THRESHOLD: int = 50
RATE_LIMIT_WINDOW: int = 10
