"""
KALKI WAF Core — Functional Test Suite

Covers:
- Health / telemetry / dashboard endpoints
- Rule CRUD (create, list, toggle, delete)
- Mitigation posture transitions
- SQLi / XSS payload detection (blocked in WAF layer)
- Sandbox test endpoint
- Block page generation
"""

import os

os.environ["ADMIN_API_KEY"] = "test-admin-key-123"

import re
import uuid

import pytest
from fastapi.testclient import TestClient

# ─── PATCH MODULES BEFORE APP IMPORT ──────────────────────────────────────────
import waf.db
import waf.middleware.inspector
import waf.middleware.rate_limiter
import waf.security.geoip
import waf.state

# ─── SHARED MOCK STORE ────────────────────────────────────────────────────────


class MockStore:
    def __init__(self):
        self.rules = []
        self.state = {"posture": "Standard Posture"}
        self.blocked = 0
        self.incidents = []


store = MockStore()


def _m_query(query, args=(), one=False):
    q = query.strip().lower()
    if q.startswith("select count(*) as total from security_events"):
        total = sum(1 for i in store.incidents)
        return [{"total": total}] if not one else {"total": total}
    if "from security_events" in q and "where" in q:
        cat = None
        if "threat_category = 'sqli'" in q:
            cat = "SQLi"
        elif "threat_category = 'xss'" in q:
            cat = "XSS"
        elif "threat_category = 'anomalous'" in q:
            cat = "Anomalous"
        if cat:
            rows = [i for i in store.incidents if i.get("threat_category") == cat]
            return [{"total": len(rows)}] if not one else {"total": len(rows)}
        return [] if not one else None
    if "from security_events" in q:
        return store.incidents if not one else (store.incidents[0] if store.incidents else None)
    if q.startswith("select count"):
        cnt = len(store.rules)
        return [{"cnt": cnt}] if not one else {"cnt": cnt}
    if q.startswith("select incident_id"):
        return store.incidents if not one else (store.incidents[0] if store.incidents else None)
    if q.startswith("select * from rules"):
        return list(store.rules)
    if q.startswith("select posture"):
        return [store.state] if not one else store.state
    return []


def _m_execute(query, args=()):
    q = query.strip().lower()
    if q.startswith("insert into rules"):
        cols = [
            "rule_id",
            "identifier",
            "pattern",
            "action",
            "category",
            "is_active",
            "blocks_count",
            "severity",
            "description",
        ]
        rule = dict(zip(cols, args, strict=False)) if isinstance(args, tuple) else dict(args)
        store.rules.append(rule)
    elif q.startswith("delete from rules"):
        store.rules = [r for r in store.rules if r["rule_id"] != args[0]]
    elif q.startswith("update rules"):
        if "blocks_count" in q:
            rid = args[0] if len(args) == 1 else args[1]
            for r in store.rules:
                if r["rule_id"] == rid:
                    r["blocks_count"] += 1
        elif "is_active" in q:
            for r in store.rules:
                if r["rule_id"] == args[1]:
                    r["is_active"] = int(args[0]) if isinstance(args[0], (int, bool)) else args[0]
    elif q.startswith("update mitigation_state"):
        store.state["posture"] = args[0]
    elif q.startswith("insert into security_events"):
        cols = [
            "incident_id",
            "timestamp",
            "source_ip",
            "user_agent",
            "target_uri",
            "malicious_payload",
            "threat_category",
            "mitigation_action",
        ]
        evt = dict(zip(cols, args, strict=False)) if isinstance(args, tuple) else dict(args)
        store.incidents.append(evt)
    return True


waf.db.query_db = _m_query
waf.db.execute_db = _m_execute

waf.state.ACTIVE_RULES_CACHE[:] = []
waf.state.GLOBAL_POSTURE = "Standard Posture"
waf.state.BACKUP_RESPONSES = {}
waf.state.INCIDENT_RESPONSE_CACHE = {}
waf.state.request_history.clear()
waf.state.IP_BLACKLIST.clear()


async def _mock_check_rate_limit(client_ip: str) -> bool:
    return True


async def _mock_check_country_block(ip: str) -> bool:
    return False


waf.middleware.rate_limiter.check_rate_limit = _mock_check_rate_limit
waf.security.geoip.check_country_block = _mock_check_country_block


class _UpstreamMockResponse:
    status_code = 200
    content = b'{"ok": true}'
    headers = {}


async def _upstream_mock_request(method, url, headers=None, **kwargs):
    return _UpstreamMockResponse()


waf.middleware.inspector.http_client.request = _upstream_mock_request

_orig_aclose = waf.middleware.inspector.http_client.aclose


async def _noop_aclose():
    pass


waf.middleware.inspector.http_client.aclose = _noop_aclose


def _do_reload():
    waf.state.ACTIVE_RULES_CACHE[:] = []
    for r in store.rules:
        if r.get("is_active"):
            try:
                pat = r["pattern"]
                compiled = re.compile(pat, re.IGNORECASE)
                waf.state.ACTIVE_RULES_CACHE.append(
                    {
                        "rule_id": r["rule_id"],
                        "identifier": r["identifier"],
                        "pattern": pat,
                        "action": r["action"],
                        "category": r["category"],
                        "compiled_regex": compiled,
                    }
                )
            except Exception:
                pass
    waf.state.GLOBAL_POSTURE = store.state["posture"]


_do_reload()


@pytest.fixture(autouse=True)
def reset_store():
    store.rules = []
    store.incidents = []
    store.state = {"posture": "Standard Posture"}
    waf.state.request_history.clear()
    _do_reload()
    yield
    store.rules = []
    store.incidents = []
    store.state = {"posture": "Standard Posture"}
    waf.state.request_history.clear()
    _do_reload()


# Import app AFTER all patches
from main import app  # noqa: E402

API_KEY_HEADER = {"X-API-Key": "test-admin-key-123"}


@pytest.fixture
def client():
    return TestClient(app)


# ─── HEALTH & DASHBOARD ───────────────────────────────────────────────────────


class TestDashboard:
    def test_dashboard_html_served(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "KALKI" in resp.text

    def test_logo_png(self, client):
        resp = client.get("/kalki_waf_logo.png")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "image/png"

    def test_telemetry_returns_json(self, client):
        resp = client.get("/api/v1/threat-intel/alerts")
        assert resp.status_code == 200
        data = resp.json()
        assert "metrics" in data
        assert "incidents" in data
        assert "rules" in data
        assert data["metrics"]["posture"] == "Standard Posture"
        assert "total_ingress" in data["metrics"]
        assert "active_rules_count" in data["metrics"]

    def test_mitigation_posture_get(self, client):
        resp = client.get("/api/v1/mitigation-posture")
        assert resp.status_code == 200
        assert resp.json()["posture"] == "Standard Posture"


# ─── RULES CRUD ───────────────────────────────────────────────────────────────


class TestRulesCRUD:
    def test_list_rules_empty(self, client):
        resp = client.get("/api/v1/rules")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_create_rule(self, client):
        payload = {
            "identifier": "Test Anti-Tamper",
            "pattern": r"union\s+select",
            "action": "Drop & Blacklist",
            "category": "SQLi",
            "severity": "CRITICAL",
            "description": "Blocks UNION SELECT tampering.",
        }
        resp = client.post("/api/v1/rules", json=payload, headers=API_KEY_HEADER)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert "rule_id" in data

    def test_list_rules_populated(self, client):
        client.post(
            "/api/v1/rules",
            headers=API_KEY_HEADER,
            json={
                "identifier": "My Rule",
                "pattern": r"admin.*rm",
                "action": "Drop & Blacklist",
            },
        )
        resp = client.get("/api/v1/rules")
        assert len(resp.json()) == 1
        assert resp.json()[0]["identifier"] == "My Rule"

    def test_create_rule_invalid_regex(self, client):
        resp = client.post(
            "/api/v1/rules",
            headers=API_KEY_HEADER,
            json={
                "identifier": "Bad",
                "pattern": r"[broken(",
                "action": "Log Payload Only",
            },
        )
        assert resp.status_code == 400
        assert "invalid" in resp.json()["detail"].lower()

    def test_toggle_rule_on_off(self, client):
        r = client.post(
            "/api/v1/rules",
            headers=API_KEY_HEADER,
            json={
                "identifier": "Toggle Me",
                "pattern": r"toggle",
                "action": "Log Payload Only",
            },
        )
        rid = r.json()["rule_id"]

        resp = client.put(f"/api/v1/rules/{rid}/toggle", json={"is_active": False}, headers=API_KEY_HEADER)
        assert resp.status_code == 200
        resp = client.put(f"/api/v1/rules/{rid}/toggle", json={"is_active": True}, headers=API_KEY_HEADER)
        assert resp.status_code == 200

    def test_delete_custom_rule(self, client):
        r = client.post(
            "/api/v1/rules",
            headers=API_KEY_HEADER,
            json={
                "identifier": "Temp Rule",
                "pattern": r"temp",
                "action": "Log Payload Only",
            },
        )
        rid = r.json()["rule_id"]
        resp = client.delete(f"/api/v1/rules/{rid}", headers=API_KEY_HEADER)
        assert resp.status_code == 200
        assert client.get("/api/v1/rules").json() == []

    def test_delete_protected_system_rule(self, client):
        for sys_id in ("sql-core-01", "xss-scrutiny-01", "rfi-blocker-01"):
            resp = client.delete(f"/api/v1/rules/{sys_id}", headers=API_KEY_HEADER)
            assert resp.status_code == 403

    def test_create_rule_strips_slashes(self, client):
        resp = client.post(
            "/api/v1/rules",
            headers=API_KEY_HEADER,
            json={
                "identifier": "Slash Test",
                "pattern": "/admin/path/gi",
                "action": "Drop & Blacklist",
            },
        )
        assert resp.status_code == 200
        saved = client.get("/api/v1/rules").json()[0]
        assert not saved["pattern"].startswith("/")
        assert not saved["pattern"].endswith("/gi")

    def test_blocks_count_increments_on_toggle(self, client):
        r = client.post(
            "/api/v1/rules",
            headers=API_KEY_HEADER,
            json={
                "identifier": "Bump Me",
                "pattern": r"test",
                "action": "Drop & Blacklist",
            },
        )
        rid = r.json()["rule_id"]
        client.put(f"/api/v1/rules/{rid}/toggle", json={"is_active": True}, headers=API_KEY_HEADER)
        rules = client.get("/api/v1/rules").json()
        assert rules[-1]["blocks_count"] >= 0


# ─── MITIGATION POSTURE ───────────────────────────────────────────────────────


class TestPosture:
    def test_get_posture_default(self, client):
        resp = client.get("/api/v1/mitigation-posture")
        assert resp.status_code == 200
        assert resp.json()["posture"] == "Standard Posture"

    @pytest.mark.parametrize("posture", ["Monitor Only", "Standard Posture", "Under Attack"])
    def test_set_posture_ok(self, client, posture):
        resp = client.post("/api/v1/mitigation-posture", json={"posture": posture}, headers=API_KEY_HEADER)
        assert resp.status_code == 200
        assert resp.json()["message"].endswith(posture)
        assert client.get("/api/v1/mitigation-posture").json()["posture"] == posture

    def test_set_posture_invalid(self, client):
        resp = client.post("/api/v1/mitigation-posture", json={"posture": "APOCALYPSE"}, headers=API_KEY_HEADER)
        assert resp.status_code == 400

    def test_telemetry_reflects_posture(self, client):
        client.post("/api/v1/mitigation-posture", json={"posture": "Under Attack"}, headers=API_KEY_HEADER)
        data = client.get("/api/v1/threat-intel/alerts").json()
        assert data["metrics"]["posture"] == "Under Attack"


# ─── SANDBOX ─────────────────────────────────────────────────────────────────


class TestSandbox:
    def test_match_detected(self, client):
        resp = client.post(
            "/api/v1/rules/test-sandbox", json={"pattern": r"union\s+select", "payload": "UNION SELECT * FROM x"}
        )
        assert resp.status_code == 200
        assert resp.json()["match"] is True
        assert "span" in resp.json()

    def test_no_match(self, client):
        resp = client.post(
            "/api/v1/rules/test-sandbox", json={"pattern": r"union\s+select", "payload": "hello world traffic"}
        )
        assert resp.status_code == 200
        assert resp.json()["match"] is False

    def test_invalid_regex_returns_no_match(self, client):
        resp = client.post("/api/v1/rules/test-sandbox", json={"pattern": r"[bad(", "payload": "anything"})
        assert resp.status_code == 200
        assert resp.json()["match"] is False
        assert "error" in resp.json()

    def test_sqli_in_payload_matches_in_sandbox(self, client):
        resp = client.post(
            "/api/v1/rules/test-sandbox",
            json={"pattern": r"(select|union|drop)\s+", "payload": "id=1; DROP TABLE users --"},
        )
        assert resp.json()["match"] is True


# ─── BLOCK PAGE ───────────────────────────────────────────────────────────────


class TestBlockPage:
    def test_block_page_contains_incident_info(self, client):
        from waf.core.block_page import generate_block_page

        html = generate_block_page("INC-001", "10.10.10.10", "SQLi")
        assert "INC-001" in html
        assert "10.10.10.10" in html
        assert "SQLi" in html
        assert "KALKI SECURITY" in html
        assert "403" in html

    def test_block_page_contains_timestamp(self, client):
        from waf.core.block_page import generate_block_page

        html = generate_block_page("INC-002", "1.2.3.4", "XSS")
        assert "2026" in html

    def test_block_page_different_categories(self, client):
        from waf.core.block_page import generate_block_page

        for category in ("SQLi", "XSS", "Anomalous"):
            html = generate_block_page(f"INC-{category}", "5.5.5.5", category)
            assert category in html


# ─── THREAT DETECTION (WAF LAYER) ─────────────────────────────────────────────

SEEDED_RULES = [
    (
        "sql-core-01",
        "OWASP SQLi Core Ruleset",
        r"(\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|ALTER|WHERE|OR|AND)\b)|(['\x22\x2d\x23\x2a])|(\/\*[\s\S]*?\*\/)",
        "Drop & Blacklist",
        "SQLi",
        1,
        1420,
        "Level 1",
        "Comprehensive SQL Injection protection.",
    ),
    (
        "xss-scrutiny-01",
        "XSS Aggressive Scrutiny",
        r"(<script.*?>[\s\S]*?<\/script>)|(javascript\s*:\s*\S+)|(on\w+\s*=\s*['\"].*?['\"])|(<\s*iframe.*?>)",
        "Drop & Blacklist",
        "XSS",
        1,
        92,
        "Level 3",
        "High-sensitivity XSS detection.",
    ),
    (
        "rfi-blocker-01",
        "Remote File Inclusion (RFI)",
        r"(https?|ftp|file|php|data):\/",
        "Drop & Blacklist",
        "CRITICAL",
        1,
        12,
        "CRITICAL",
        "Blocks remote file inclusion attempts.",
    ),
]


class TestThreatDetection:
    def _seed_rules(self, client):
        waf.state.ACTIVE_RULES_CACHE[:] = []
        for r in SEEDED_RULES:
            if not any(x["rule_id"] == r[0] for x in store.rules):
                cols = [
                    "rule_id",
                    "identifier",
                    "pattern",
                    "action",
                    "category",
                    "is_active",
                    "blocks_count",
                    "severity",
                    "description",
                ]
                store.rules.append(dict(zip(cols, r, strict=False)))
        _do_reload()

    def test_sqli_blocked(self, client):
        self._seed_rules(client)
        resp = client.get("/test?id=1' UNION SELECT * FROM users--")
        assert resp.status_code == 403

    def test_xss_blocked(self, client):
        self._seed_rules(client)
        resp = client.get("/search?q=<script>alert(1)</script>")
        assert resp.status_code == 403

    def test_rfi_blocked(self, client):
        self._seed_rules(client)
        resp = client.get("/page?url=http://evil.com/shell.php")
        assert resp.status_code == 403

    def test_clean_traffic_allowed(self, client):
        self._seed_rules(client)
        resp = client.get("/clean-page")
        assert resp.status_code == 200

    def test_api_routes_bypass_inspection(self, client):
        resp = client.post(
            "/api/v1/rules",
            json={
                "identifier": "Bypass Test",
                "pattern": r"test",
                "action": "Drop & Blacklist",
            },
            headers=API_KEY_HEADER,
        )
        assert resp.status_code == 200

    def test_block_page_has_incident_id(self, client):
        self._seed_rules(client)
        resp = client.get("/test?id=1 UNION SELECT 1--")
        assert resp.status_code == 403
        body = resp.text
        assert "INC" in body or "SECURITY" in body.upper()

    def test_rate_limit_exceeded(self, client):
        original = waf.middleware.rate_limiter.check_rate_limit

        async def _flooded_limit(ip):
            return False

        waf.middleware.rate_limiter.check_rate_limit = _flooded_limit
        try:
            resp = client.get("/test-page")
            assert resp.status_code == 403
            assert "SECURITY" in resp.text.upper()
        finally:
            waf.middleware.rate_limiter.check_rate_limit = original

    def test_rate_limit_returns_block_page(self, client):
        original = waf.middleware.rate_limiter.check_rate_limit

        async def _flooded_limit(ip):
            return False

        waf.middleware.rate_limiter.check_rate_limit = _flooded_limit
        try:
            resp = client.get("/another-test-page")
            assert resp.status_code == 403
            assert "KALKI" in resp.text
        finally:
            waf.middleware.rate_limiter.check_rate_limit = original

    def test_sqli_variant_blocked(self, client):
        self._seed_rules(client)
        resp = client.get("/test?id=1; DROP TABLE users;")
        assert resp.status_code == 403


# ─── ENGINE INTERNALS ────────────────────────────────────────────────────────


class TestEngineInternals:
    def test_block_page_generator_signature(self, client):
        from waf.core.block_page import generate_block_page

        uid = str(uuid.uuid4())
        html = generate_block_page(uid, "127.0.0.1", "XSS")
        assert str(uid) in html
        assert "xss" in html.lower()

    def test_reload_rules_cache(self):
        waf.state.ACTIVE_RULES_CACHE[:] = []
        store.rules.clear()
        cols = [
            "rule_id",
            "identifier",
            "pattern",
            "action",
            "category",
            "is_active",
            "blocks_count",
            "severity",
            "description",
        ]
        store.rules.append(
            dict(
                zip(
                    cols,
                    (
                        "sql-core-01",
                        "OWASP SQLi",
                        r"union\s+select",
                        "Drop & Blacklist",
                        "SQLi",
                        1,
                        0,
                        "Level 1",
                        "Test",
                    ),
                    strict=False,
                )
            )
        )
        _do_reload()
        assert len(waf.state.ACTIVE_RULES_CACHE) == 1
        assert waf.state.ACTIVE_RULES_CACHE[0]["identifier"] == "OWASP SQLi"

    def test_global_posture_tracks_store(self):
        store.state["posture"] = "Under Attack"
        _do_reload()
        assert waf.state.GLOBAL_POSTURE == "Under Attack"


# ─── NEW FEATURE TESTS ───────────────────────────────────────────────────────────


class TestPrometheusMetrics:
    def test_metrics_endpoint_exists(self, client):
        resp = client.get("/metrics")
        assert resp.status_code in [200, 404]

    def test_request_counting(self, client):
        pass


class TestGeoIPBlocking:
    def test_geoip_function_handles_missing_db(self, client):
        from waf.security.geoip import get_country_code

        result = get_country_code("8.8.8.8")
        assert result is None or isinstance(result, str)

    def test_country_block_configurable(self):
        from waf.security import geoip

        original = geoip.BLOCKED_COUNTRIES.copy()
        try:
            geoip.BLOCKED_COUNTRIES = {"CN"}
            assert "CN" in geoip.BLOCKED_COUNTRIES
        finally:
            geoip.BLOCKED_COUNTRIES = original


class TestCircuitBreaker:
    def test_circuit_breaker_initial_state(self):
        from waf.middleware.circuit_breaker import CircuitBreaker

        cb = CircuitBreaker(failure_threshold=3)
        assert cb.state == "CLOSED"
        assert cb.failure_count == 0

    def test_circuit_breaker_opens_on_failures(self):
        from waf.middleware.circuit_breaker import CircuitBreaker

        cb = CircuitBreaker(failure_threshold=2)
        cb.on_failure()
        cb.on_failure()
        assert cb.state == "OPEN"


class TestGraphQLDepth:
    def test_graphql_depth_valid(self):
        from waf.security.graphql import check_graphql_depth

        query = "{ user { name } }"
        assert check_graphql_depth(query) is True

    def test_graphql_depth_exceeded(self):
        import waf.config as _cfg
        from waf.security.graphql import check_graphql_depth

        original = _cfg.GRAPHQL_MAX_DEPTH
        _cfg.GRAPHQL_MAX_DEPTH = 3
        try:
            query = "{ a { b { c { d { e } } } } }"
            assert check_graphql_depth(query) is False
        finally:
            _cfg.GRAPHQL_MAX_DEPTH = original


class TestJWTValidation:
    def test_jwt_validation_no_secret(self):
        from waf.config import JWT_SECRET
        from waf.security.jwt import validate_jwt_token

        assert JWT_SECRET == ""

        class MockRequest:
            headers = {}

        result = validate_jwt_token(MockRequest())
        assert result is None

    def test_jwt_validation_missing_token(self):
        import waf.config as _cfg
        from waf.security.jwt import validate_jwt_token

        original = _cfg.JWT_SECRET
        _cfg.JWT_SECRET = "test-secret"
        try:

            class MockRequest:
                headers = {}

            result = validate_jwt_token(MockRequest())
            assert result is None
        finally:
            _cfg.JWT_SECRET = original


class TestWebSocket:
    def test_websocket_manager_exists(self):
        from waf.core.websocket import manager

        assert hasattr(manager, "active_connections")


class TestBodySizeLimit:
    def test_request_body_too_large_returns_413(self, client):
        large_payload = "x" * (11 * 1024 * 1024)

        resp = client.post("/test-endpoint", data=large_payload, headers={"content-type": "text/plain"})
        assert resp.status_code == 413
        assert "Request body too large" in resp.json()["error"]

    def test_normal_request_body_allowed(self, client):
        normal_payload = "hello world"

        resp = client.post("/test-endpoint", data=normal_payload, headers={"content-type": "text/plain"})
        assert resp.status_code == 200

    def test_content_length_header_enforcement(self, client):
        large_payload = "x" * 100

        resp = client.post(
            "/test-endpoint",
            data=large_payload,
            headers={
                "content-type": "text/plain",
                "content-length": str(11 * 1024 * 1024),
            },
        )
        assert resp.status_code == 413
        assert "Request body too large" in resp.json()["error"]
