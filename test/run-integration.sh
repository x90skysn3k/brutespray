#!/usr/bin/env -S bash
###############################################################################
# BruteSpray Integration Test Runner
#
# Starts the Docker Compose test environment, waits for all services to become
# healthy, runs brutespray against each service with known-good credentials,
# verifies that each attempt succeeds, and tears everything down.
#
# Exit codes:
#   0  All tests passed
#   1  One or more tests failed
#   2  Environment setup failed
###############################################################################
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
OUTPUT_DIR="${SCRIPT_DIR}/integration-output"

# Colours (disabled if not a terminal)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' CYAN='' NC=''
fi

info()  { echo -e "${CYAN}[*]${NC} $*"; }
pass()  { echo -e "${GREEN}[+]${NC} $*"; }
fail()  { echo -e "${RED}[-]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }

FAILURES=0
TESTS_RUN=0

###############################################################################
# Resolve brutespray binary
###############################################################################
BRUTESPRAY=""
if [ -x "${PROJECT_ROOT}/brutespray-bin" ]; then
    BRUTESPRAY="${PROJECT_ROOT}/brutespray-bin"
elif command -v brutespray &>/dev/null; then
    BRUTESPRAY="$(command -v brutespray)"
else
    warn "brutespray binary not found. Building..."
    (cd "${PROJECT_ROOT}" && go build -o brutespray-bin .)
    BRUTESPRAY="${PROJECT_ROOT}/brutespray-bin"
fi
info "Using brutespray: ${BRUTESPRAY}"

###############################################################################
# Cleanup handler
###############################################################################
cleanup() {
    info "Tearing down test environment..."
    docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans 2>/dev/null || true
    info "Cleanup complete."
}
trap cleanup EXIT

###############################################################################
# Start environment
###############################################################################
info "Starting Docker Compose test environment..."
docker compose -f "${COMPOSE_FILE}" up -d --wait 2>&1 || true

###############################################################################
# Wait for healthy services (up to 120 seconds total)
###############################################################################
info "Waiting for services to become healthy..."
MAX_WAIT=120
INTERVAL=5
ELAPSED=0

wait_for_service() {
    local name="$1"
    local host="$2"
    local port="$3"
    local secs=0
    while ! (echo >/dev/tcp/"$host"/"$port") 2>/dev/null; do
        sleep 1
        secs=$((secs + 1))
        if [ "$secs" -ge "$MAX_WAIT" ]; then
            warn "Timeout waiting for ${name} on port ${port}"
            return 1
        fi
    done
    return 0
}

SERVICES_PORTS=(
    "SSH:127.0.0.1:20022"
    "FTP:127.0.0.1:20021"
    "SMTP:127.0.0.1:20025"
    "POP3:127.0.0.1:20110"
    "IMAP:127.0.0.1:20143"
    "HTTP-Basic:127.0.0.1:20080"
    "HTTP-Digest:127.0.0.1:20081"
    "Samba:127.0.0.1:20445"
    "MySQL:127.0.0.1:23306"
    "PostgreSQL:127.0.0.1:25432"
    "Redis:127.0.0.1:26379"
    "MongoDB:127.0.0.1:27018"
    "VNC:127.0.0.1:25900"
    "Telnet:127.0.0.1:20023"
)

ALL_READY=true
for entry in "${SERVICES_PORTS[@]}"; do
    IFS=: read -r name host port <<< "$entry"
    if wait_for_service "$name" "$host" "$port"; then
        pass "${name} is listening on port ${port}"
    else
        fail "${name} is NOT ready on port ${port}"
        ALL_READY=false
    fi
done

if [ "$ALL_READY" = false ]; then
    warn "Some services did not start. Continuing with available services..."
fi

# Give services extra time to fully initialise after ports open
info "Giving services 10 seconds to fully initialise..."
sleep 10

###############################################################################
# Prepare output directory
###############################################################################
rm -rf "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}"

###############################################################################
# Test helper
###############################################################################
run_test() {
    local test_name="$1"
    shift
    local args=("$@")

    TESTS_RUN=$((TESTS_RUN + 1))
    info "Test ${TESTS_RUN}: ${test_name}"

    local out_file="${OUTPUT_DIR}/${test_name// /_}.log"

    if "${BRUTESPRAY}" "${args[@]}" -nc -no-tui -t 1 -T 1 -w 15s -o "${OUTPUT_DIR}" 2>&1 | tee "${out_file}"; then
        # Check if output contains SUCCESS
        if grep -qi "success" "${out_file}" 2>/dev/null; then
            pass "PASS: ${test_name}"
            return 0
        fi
        # Also check the output directory for service-specific files
        if find "${OUTPUT_DIR}" -name "*.txt" -newer "${out_file}" 2>/dev/null | head -1 | grep -q .; then
            pass "PASS: ${test_name} (output file created)"
            return 0
        fi
    fi

    fail "FAIL: ${test_name}"
    FAILURES=$((FAILURES + 1))
    return 1
}

###############################################################################
# Run tests
###############################################################################
info "============================================================"
info "  Running BruteSpray Integration Tests"
info "============================================================"
echo

# --- SSH ---
run_test "SSH brute-force" \
    -H "ssh://127.0.0.1:20022" \
    -u testuser -p testpass \
    --stop-on-success || true

# --- FTP ---
run_test "FTP brute-force" \
    -H "ftp://127.0.0.1:20021" \
    -u ftpuser -p ftppass \
    --stop-on-success || true

# --- SMTP ---
run_test "SMTP brute-force" \
    -H "smtp://127.0.0.1:20025" \
    -u "test@test.local" -p testpass \
    --stop-on-success || true

# --- POP3 ---
run_test "POP3 brute-force" \
    -H "pop3://127.0.0.1:20110" \
    -u "test@test.local" -p testpass \
    --stop-on-success || true

# --- IMAP ---
run_test "IMAP brute-force" \
    -H "imap://127.0.0.1:20143" \
    -u "test@test.local" -p testpass \
    --stop-on-success || true

# --- HTTP Basic Auth ---
run_test "HTTP Basic Auth brute-force" \
    -H "http://127.0.0.1:20080" \
    -u admin -p secret \
    -m "auth:BASIC" \
    --stop-on-success || true

# --- HTTP Digest Auth ---
run_test "HTTP Digest Auth brute-force" \
    -H "http://127.0.0.1:20081" \
    -u admin -p secret \
    -m "auth:DIGEST" \
    --stop-on-success || true

# --- Samba / SMB ---
run_test "SMB brute-force" \
    -H "smbnt://127.0.0.1:20445" \
    -u smbuser -p smbpass \
    --stop-on-success || true

# --- MySQL ---
run_test "MySQL brute-force" \
    -H "mysql://127.0.0.1:23306" \
    -u root -p rootpass \
    --stop-on-success || true

# --- PostgreSQL ---
run_test "PostgreSQL brute-force" \
    -H "postgres://127.0.0.1:25432" \
    -u postgres -p pgpass \
    --stop-on-success || true

# --- Redis ---
run_test "Redis brute-force" \
    -H "redis://127.0.0.1:26379" \
    -u default -p testpass \
    --stop-on-success || true

# --- MongoDB ---
run_test "MongoDB brute-force" \
    -H "mongodb://127.0.0.1:27018" \
    -u admin -p mongopass \
    --stop-on-success || true

# --- VNC ---
run_test "VNC brute-force" \
    -H "vnc://127.0.0.1:25900" \
    -p vncpass \
    --stop-on-success || true

# --- Telnet ---
run_test "Telnet brute-force" \
    -H "telnet://127.0.0.1:20023" \
    -u testuser -p testpass \
    --stop-on-success || true

###############################################################################
# Summary
###############################################################################
echo
info "============================================================"
info "  Integration Test Summary"
info "============================================================"
info "Tests run:    ${TESTS_RUN}"
if [ "${FAILURES}" -eq 0 ]; then
    pass "All ${TESTS_RUN} tests passed!"
    exit 0
else
    fail "${FAILURES} of ${TESTS_RUN} tests FAILED"
    exit 1
fi
