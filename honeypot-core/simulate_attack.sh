#!/bin/bash
# simulate_attack.sh - Run this to demo the honeypot detection
# Usage: ./simulate_attack.sh [host] [port]

HOST=${1:-localhost}
PORT=${2:-8080}
BASE="http://$HOST:$PORT"

echo "=== Honeypot Attack Simulation ==="
echo "Target: $BASE"
echo ""

# Phase 1: Reconnaissance
echo "[Phase 1] Reconnaissance - probing common endpoints..."
sleep 1

curl -s "$BASE/" > /dev/null
echo "  GET / (homepage)"

curl -s "$BASE/health" > /dev/null
echo "  GET /health (health check)"

curl -s "$BASE/admin" > /dev/null
echo "  GET /admin (admin probe) +25 points"

curl -s "$BASE/config" > /dev/null
echo "  GET /config (config probe) +30 points"

curl -s "$BASE/backup" > /dev/null
echo "  GET /backup (backup probe) +30 points"

echo ""
sleep 2

# Phase 2: Login attempts (credential stuffing pattern)
echo "[Phase 2] Credential stuffing - multiple login attempts..."
sleep 1

curl -s -X POST "$BASE/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' > /dev/null
echo "  POST /login (admin:admin123)"

curl -s -X POST "$BASE/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"root","password":"toor"}' > /dev/null
echo "  POST /login (root:toor) +25 points (suspicious username)"

curl -s -X POST "$BASE/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test"}' > /dev/null
echo "  POST /login (test:test)"

curl -s -X POST "$BASE/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"sa","password":"password"}' > /dev/null
echo "  POST /login (sa:password) +25 points"

echo ""
sleep 2

# Phase 3: SQLi attempt
echo "[Phase 3] SQL Injection attempt..."
sleep 1

curl -s -X POST "$BASE/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\'' OR 1=1 --","password":"x"}' > /dev/null
echo "  POST /login with SQLi payload +25 points"

curl -s "$BASE/api/users?id=1%20UNION%20SELECT%20*%20FROM%20passwords" > /dev/null
echo "  GET /api/users with UNION SELECT +25 points"

echo ""
sleep 2

# Phase 4: Path traversal / LFI
echo "[Phase 4] LFI / Path traversal..."
sleep 1

curl -s "$BASE/api/files?path=../../../etc/passwd" > /dev/null
echo "  GET /api/files?path=../../../etc/passwd +25 points"

curl -s "$BASE/api/download?file=....//....//etc/shadow" > /dev/null
echo "  Path traversal attempt +25 points"

echo ""
sleep 2

# Phase 5: RCE attempt
echo "[Phase 5] RCE attempt..."
sleep 1

curl -s "$BASE/api/exec?cmd=whoami" > /dev/null
echo "  GET /api/exec?cmd=whoami +35 points"

curl -s -X POST "$BASE/api/run" \
  -H "Content-Type: application/json" \
  -d '{"command":"bash -c \"cat /etc/passwd\""}' > /dev/null
echo "  POST with bash -c payload +35 points"

echo ""
sleep 2

# Phase 6: Scanner-like burst
echo "[Phase 6] Scanner burst - rapid endpoint sweep..."
sleep 1

for endpoint in "/.env" "/.git/config" "/wp-admin" "/phpmyadmin" \
  "/actuator" "/debug" "/trace" "/metrics" "/swagger.json" "/graphql"; do
  curl -s "$BASE$endpoint" > /dev/null &
done
wait
echo "  Swept 10 endpoints in burst +15 points (path-sweep)"

echo ""
echo "=== Simulation Complete ==="
echo ""
echo "Check detection results:"
echo "  curl $BASE/api/detection/leaderboard"
echo "  curl $BASE/api/detection/alerts"
echo "  curl '$BASE/api/detection/ip/127.0.0.1'"