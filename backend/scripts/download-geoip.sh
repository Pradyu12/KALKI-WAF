#!/usr/bin/env bash
set -euo pipefail

# Download GeoLite2 databases from MaxMind
# Requires a free MaxMind account: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
#
# Usage:
#   MAXMIND_LICENSE_KEY=your_key_here bash scripts/download-geoip.sh
#   # or set the env var before running

LICENSE_KEY="${MAXMIND_LICENSE_KEY:-}"
EDITION_CITY="GeoLite2-City"
EDITION_COUNTRY="GeoLite2-Country"
BASE_URL="https://download.maxmind.com/app/geoip_download"

if [ -z "$LICENSE_KEY" ]; then
  echo "ERROR: MAXMIND_LICENSE_KEY not set."
  echo ""
  echo "1. Create a free MaxMind account at https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
  echo "2. Generate a license key at https://www.maxmind.com/en/accounts/current/license-key"
  echo "3. Run: MAXMIND_LICENSE_KEY=your_key bash scripts/download-geoip.sh"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCRIPT_DIR"

for EDITION in "$EDITION_CITY" "$EDITION_COUNTRY"; do
  echo "Downloading $EDITION..."
  if curl -sSL -o /tmp/${EDITION}.tar.gz \
    "${BASE_URL}?edition_id=${EDITION}&license_key=${LICENSE_KEY}&suffix=tar.gz"; then
    tar xzf /tmp/${EDITION}.tar.gz -C /tmp/
    cp /tmp/${EDITION}*/${EDITION}.mmdb .
    echo "  -> ${EDITION}.mmdb saved"
  else
    echo "  FAILED to download $EDITION"
  fi
done

ls -lh GeoLite2-*.mmdb 2>/dev/null || echo "No GeoIP databases found."
echo ""
echo "Done. Restart the WAF to load the databases."
