import os
import threading
from functools import lru_cache

import geoip2.database

from waf.config import BLOCKED_COUNTRIES as CONFIG_BLOCKED_COUNTRIES
from waf.config import GEOIP_CITY_DB_PATH, GEOIP_DB_PATH

geoip_reader: geoip2.database.Reader | None = None
geoip_city_reader: geoip2.database.Reader | None = None
BLOCKED_COUNTRIES: set[str] = CONFIG_BLOCKED_COUNTRIES

# Cache for live API lookups to avoid hammering ip-api.com
_geo_cache: dict[str, dict] = {}
_geo_cache_lock = threading.Lock()


async def init_geoip():
    global geoip_reader, geoip_city_reader
    _load_reader(GEOIP_DB_PATH, "GeoIP2 Country", "geoip_reader")
    _load_reader(GEOIP_CITY_DB_PATH, "GeoIP2 City", "geoip_city_reader")


def _load_reader(path: str, label: str, attr: str):
    global geoip_reader, geoip_city_reader
    try:
        if os.path.exists(path):
            reader = geoip2.database.Reader(path)
            globals()[attr] = reader
            print(f"[INFO] {label} database loaded from {path}")
        else:
            print(f"[WARN] {label} database not found at {path} — will use live API fallback")
    except Exception as e:
        print(f"[WARN] {label} initialization failed: {e}")


def _is_private_ip(ip: str) -> bool:
    """Return True for private/loopback IPs that can't be geolocated."""
    try:
        parts = [int(p) for p in ip.split(".")]
        if len(parts) != 4:
            return True
        a, b = parts[0], parts[1]
        return (
            a == 10
            or a == 127
            or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168)
            or a == 0
        )
    except Exception:
        return True


def _live_geo_lookup(ip: str) -> dict | None:
    """Query ip-api.com for live geolocation. Returns None on failure."""
    if _is_private_ip(ip):
        return None
    with _geo_cache_lock:
        if ip in _geo_cache:
            return _geo_cache[ip]
    try:
        import urllib.request
        import json as _json
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon"
        with urllib.request.urlopen(url, timeout=3) as resp:
            data = _json.loads(resp.read().decode())
        if data.get("status") == "success":
            result = {
                "lat": round(data.get("lat", 0), 4),
                "lon": round(data.get("lon", 0), 4),
                "city": data.get("city"),
                "country": data.get("countryCode"),
                "source": "live_api",
            }
            with _geo_cache_lock:
                # Keep cache bounded
                if len(_geo_cache) > 5000:
                    _geo_cache.clear()
                _geo_cache[ip] = result
            return result
    except Exception:
        pass
    return None


def get_country_code(ip: str) -> str | None:
    if geoip_reader:
        try:
            response = geoip_reader.country(ip)
            return response.country.iso_code
        except Exception:
            pass
    # Fallback: live API
    geo = _live_geo_lookup(ip)
    if geo:
        return geo.get("country")
    return None


def get_geo_location(ip: str) -> dict:
    # 1. Try city DB (most accurate)
    if geoip_city_reader:
        try:
            response = geoip_city_reader.city(ip)
            loc = response.location
            return {
                "lat": round(loc.latitude, 4) if loc and loc.latitude else None,
                "lon": round(loc.longitude, 4) if loc and loc.longitude else None,
                "city": response.city.name if response.city else None,
                "country": response.country.iso_code if response.country else None,
                "source": "city_db",
            }
        except Exception:
            pass

    # 2. Try country DB
    if geoip_reader:
        try:
            response = geoip_reader.country(ip)
            country = response.country.iso_code if response.country else None
            # Still try live API for coords
            live = _live_geo_lookup(ip)
            if live:
                return {**live, "country": country or live.get("country"), "source": "country_db+api"}
            return {
                "lat": None,
                "lon": None,
                "city": None,
                "country": country,
                "source": "country_db",
            }
        except Exception:
            pass

    # 3. Live API fallback (no .mmdb files)
    live = _live_geo_lookup(ip)
    if live:
        return live

    # 4. Private/unknown IP
    return {
        "lat": None,
        "lon": None,
        "city": None,
        "country": None,
        "source": "unknown",
    }


async def check_country_block(ip: str) -> bool:
    if not BLOCKED_COUNTRIES:
        return False
    country = get_country_code(ip)
    return country in BLOCKED_COUNTRIES
