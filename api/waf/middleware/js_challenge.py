import hashlib
import hmac
import json
import time
import uuid

from fastapi import Request
from fastapi.responses import HTMLResponse

from waf.config import JS_CHALLENGE_SECRET

_CHALLENGE_TTL = 300  # 5 minutes to solve
_COOKIE_TTL = 3600  # cookie valid for 1 hour after solving
_COOKIE_NAME = "kalki_cf_challenge"


def _sign(payload: str) -> str:
    return hmac.new(JS_CHALLENGE_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]


def _verify_challenge_token(token: str, ip: str, timestamp: int) -> bool:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return False
        ts_str, nonce, sig = parts
        actual_ts = int(ts_str)
        if abs(time.time() - actual_ts) > _CHALLENGE_TTL:
            return False
        expected = _sign(f"{ts_str}.{ip}.{nonce}")
        return hmac.compare_digest(sig, expected)
    except (ValueError, IndexError):
        return False


def generate_challenge_page(request: Request, reason: str = "security") -> HTMLResponse:
    """Return an HTML challenge page requiring the client to solve a PoW."""
    ip = request.client.host if request.client else "0.0.0.0"
    challenge_id = str(uuid.uuid4())[:8]
    ts = int(time.time())
    nonce_hex = uuid.uuid4().hex[:8]
    token = f"{ts}.{nonce_hex}.{_sign(f'{ts}.{ip}.{nonce_hex}')}"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Checking your browser</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ background:#0a0617; color:#e0d4ff; font-family:system-ui,sans-serif; display:flex; align-items:center; justify-content:center; min-height:100vh; }}
.card {{ background:rgba(156,39,176,.08); border:1px solid rgba(156,39,176,.25); border-radius:16px; padding:40px; text-align:center; max-width:420px; }}
.spinner {{ width:40px;height:40px;margin:20px auto;border:3px solid rgba(156,39,176,.15);border-top:3px solid #9c27b0;border-radius:50%;animation:spin .8s linear infinite; }}
@keyframes spin {{ to {{ transform:rotate(360deg); }} }}
h2 {{ margin-bottom:8px; }}
p {{ color:#a99bc5;font-size:14px; }}
</style></head>
<body>
<div class="card">
<h2>Checking your browser</h2>
<p>Please wait while we verify your browser is legitimate.</p>
<div class="spinner"></div>
</div>
<script>
(async()=>{{
const prefix='0000';  // difficulty
const ts={ts};
const ip={json.dumps(ip)};
const challenge='{challenge_id}';
const token='{token}';
async function solve() {{
    for(let n=0;n<1e7;n++){{
        const h=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(ts+ip+n));
        const b=Array.from(new Uint8Array(h)).map(b=>b.toString(16).padStart(2,'0')).join('');
        if(b.startsWith(prefix)){{
            document.cookie='{_COOKIE_NAME}='+token+'.'+n+';path=/;max-age={_COOKIE_TTL};samesite=strict' + (location.protocol==='https:'?';secure':'');
            location.reload();
            return;
        }}
    }}
    setTimeout(solve,100);
}}
solve();
}})();
</script>
</body></html>"""
    return HTMLResponse(content=html, status_code=403)


def validate_challenge(request: Request) -> bool:
    """Check if the request has a valid JS challenge cookie."""
    cookie = request.cookies.get(_COOKIE_NAME)
    if not cookie:
        return False

    parts = cookie.rsplit(".", 1)
    if len(parts) != 2:
        return False
    token, nonce = parts

    ip = request.client.host if request.client else "0.0.0.0"
    ts_str = token.split(".")[0] if "." in token else ""
    if not ts_str.isdigit():
        return False
    ts = int(ts_str)
    if abs(time.time() - ts) > _COOKIE_TTL:
        return False

    if not _verify_challenge_token(token, ip, ts):
        return False

    # Verify PoW nonce
    try:
        digest = hashlib.sha256(f"{ts}.{ip}.{nonce}".encode()).hexdigest()
    except Exception:
        return False
    return digest.startswith("0000")
