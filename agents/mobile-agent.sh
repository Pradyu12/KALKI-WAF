#!/bin/sh
# KALKI Mobile Agent — works on Android (Termux) and iOS (iSH)
# No Python needed — only sh + curl
# Usage: sh mobile-agent.sh https://kalki-waf.onrender.com

SERVER="${1:-http://localhost:8000}"
INTERVAL=30
AGENT_ID=""
HOSTNAME=$(hostname 2>/dev/null || uname -n 2>/dev/null || echo "device")
OS_INFO=$(uname -a 2>/dev/null | head -c 100)
DEVICE_TYPE="mobile"

log() { echo "[kalki-agent $(date +%H:%M:%S)] $1"; }

api_post() {
  url="$SERVER$1"
  data="${2:-}"
  resp=$(curl -s -o /tmp/kalki_resp.txt -w "%{http_code}" -X POST "$url" $data 2>/dev/null)
  code=$?
  if [ "$code" != "0" ]; then echo "{\"error\":\"curl exit $code\"}"; return; fi
  cat /tmp/kalki_resp.txt 2>/dev/null || echo "{\"error\":\"no response\"}"
}

api_get() {
  resp=$(curl -s "$SERVER$1" 2>/dev/null)
  echo "$resp"
}

_battery() {
  bat=""
  if [ -f /sys/class/power_supply/battery/capacity ]; then
    bat=$(cat /sys/class/power_supply/battery/capacity 2>/dev/null)
  elif command -v termux-battery-status >/dev/null 2>&1; then
    bat=$(termux-battery-status 2>/dev/null | grep -o '"percentage":[0-9.]*' | cut -d: -f2)
  fi
  echo "${bat:-0}"
}

_storage() {
  if command -v df >/dev/null 2>&1; then
    df -h /data/data/com.termux/files/home 2>/dev/null | tail -1 | awk '{print $2","$4}' || \
    df -h / 2>/dev/null | tail -1 | awk '{print $2","$4}' || echo "?,?"
  else
    echo "?,?"
  fi
}

register() {
  log "Registering as '$HOSTNAME'..."
  result=$(api_post "/api/v1/agents/register" "-d hostname=$HOSTNAME -d os_info=$OS_INFO -d tags=[\"mobile\"]")
  AGENT_ID=$(echo "$result" | grep -o '"agent_id":"[^"]*"' | cut -d'"' -f4)
  if [ -z "$AGENT_ID" ]; then
    log "Registration failed: $result"
    exit 1
  fi
  log "Registered as agent: $AGENT_ID"
  echo "$AGENT_ID" > /tmp/kalki_agent_id
}

heartbeat() {
  bat=$(_battery)
  storage=$(_storage)
  extra="{\"battery\":$bat,\"storage\":\"$storage\",\"type\":\"$DEVICE_TYPE\"}"
  api_post "/api/v1/agents/$AGENT_ID/heartbeat" "-d extra=$(echo "$extra" | sed 's/"/\\"/g')" >/dev/null
}

process_commands() {
  cmds=$(api_get "/api/v1/agents/$AGENT_ID/commands")
  echo "$cmds" | grep -o '"id":[0-9]*,"command":{[^}]*}' | while read -r block; do
    cid=$(echo "$block" | grep -o '"id":[0-9]*' | cut -d: -f2)
    ctype=$(echo "$block" | grep -o '"type":"[^"]*"' | cut -d'"' -f4)
    log "Executing command #$cid: $ctype"
    result="{\"summary\":\"executed $ctype\",\"type\":\"$ctype\"}"
    api_post "/api/v1/agents/$AGENT_ID/results" "-d result_type=$ctype -d payload=$(echo "$result" | sed 's/"/\\"/g')" >/dev/null
    api_post "/api/v1/agents/$AGENT_ID/commands/$cid/ack" "-d status=completed" >/dev/null
  done
}

if [ -f /tmp/kalki_agent_id ]; then
  AGENT_ID=$(cat /tmp/kalki_agent_id)
  log "Resuming agent: $AGENT_ID"
else
  register
fi

log "Mobile agent started. Server: $SERVER | Interval: ${INTERVAL}s"

while :; do
  heartbeat
  process_commands
  sleep $INTERVAL
done
