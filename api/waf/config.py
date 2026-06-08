import os

JWT_SECRET: str = os.getenv("JWT_SECRET", "")
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

# ─── P1-D Security hardening ────────────────────────────────────────────────────────

ENV: str = os.getenv("ENV", "development").lower()
IS_PRODUCTION: bool = ENV == "production"

CORS_ORIGINS: list[str] = (
    os.getenv("CORS_ORIGINS", "").split(",") if os.getenv("CORS_ORIGINS") else (["*"] if not IS_PRODUCTION else [])
)
if IS_PRODUCTION and not CORS_ORIGINS:
    print("[WARN] ENV=production but CORS_ORIGINS is empty — API will only accept same-origin requests.")
    CORS_ORIGINS = []

TRUSTED_IPS: set[str] = set(os.getenv("TRUSTED_IPS", "").split(",")) if os.getenv("TRUSTED_IPS") else set()

SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "0",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
}

DLP_ENABLED: bool = os.getenv("DLP_ENABLED", "true").lower() in ("true", "1", "yes")
JS_CHALLENGE_SECRET: str = os.getenv("JS_CHALLENGE_SECRET", "kalki-js-challenge-secret-change-me")
CSRF_ENABLED: bool = os.getenv("CSRF_ENABLED", "false").lower() in ("true", "1", "yes")
CSRF_SECRET: str = os.getenv("CSRF_SECRET", "kalki-csrf-secret-change-me")
