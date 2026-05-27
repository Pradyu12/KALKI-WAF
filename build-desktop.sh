#!/bin/bash
# Build KALKI Desktop as a standalone executable
# Usage: bash build-desktop.sh

set -e

echo "==> Installing build dependencies..."
pip install pyinstaller requests sseclient-py pillow pystray

echo "==> Building executable..."
cd "$(dirname "$0")"

LOGO="frontend/kalki_waf_logo.png"

pyinstaller --onefile --windowed \
  --name "KALKI-Desktop" \
  --add-data "$LOGO:kalki_waf_logo.png" \
  --icon "$LOGO" \
  --hidden-import plyer \
  --hidden-import pystray \
  --hidden-import PIL \
  --hidden-import PIL._tkinter_finder \
  kalki-desktop.py

echo ""
echo "==> Done! Executable at: dist/KALKI-Desktop"
ls -lh dist/KALKI-Desktop*
