import os

import geoip2.database

from waf.config import BLOCKED_COUNTRIES as CONFIG_BLOCKED_COUNTRIES
from waf.config import GEOIP_CITY_DB_PATH, GEOIP_DB_PATH

geoip_reader: geoip2.database.Reader | None = None
geoip_city_reader: geoip2.database.Reader | None = None
BLOCKED_COUNTRIES: set[str] = CONFIG_BLOCKED_COUNTRIES


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
            print(f"[WARN] {label} database not found at {path}")
    except Exception as e:
        print(f"[WARN] {label} initialization failed: {e}")


def get_country_code(ip: str) -> str | None:
    if geoip_reader:
        try:
            response = geoip_reader.country(ip)
            return response.country.iso_code
        except Exception:
            pass
    return None


def get_geo_location(ip: str) -> dict:
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
    if geoip_reader:
        try:
            response = geoip_reader.country(ip)
            lat, lon = _ip_to_approx_coords(ip)
            return {
                "lat": lat,
                "lon": lon,
                "city": None,
                "country": response.country.iso_code if response.country else None,
                "source": "country_db",
            }
        except Exception:
            pass
    lat, lon = _ip_to_approx_coords(ip)
    return {
        "lat": lat,
        "lon": lon,
        "city": None,
        "country": None,
        "source": "approx",
    }


def _ip_to_approx_coords(ip: str) -> tuple[float, float]:
    parts = ip.split(".")
    try:
        ip_num = (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])
    except (IndexError, ValueError):
        return (0.0, 0.0)
    lat = ((ip_num * 7) % 180) - 90
    lon = ((ip_num * 13) % 360) - 180
    return (round(lat, 4), round(lon, 4))


async def check_country_block(ip: str) -> bool:
    if not BLOCKED_COUNTRIES:
        return False
    country = get_country_code(ip)
    return country in BLOCKED_COUNTRIES
