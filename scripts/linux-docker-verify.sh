#!/usr/bin/env bash
# HegoSentinel — Sprint 7 Real Linux Docker Worker Containment Verification (WKR-001..WKR-005)
# Analyzes exit code, stdout, and stderr for every docker run check; rejects Docker CLI errors (125/126/127)
# and saves verifiable evidence to reports/linux-docker-evidence.json.
set -euo pipefail

IMAGE_TAG="hegosentinel-worker:0.1.0-alpha.4"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SAMPLE_REPO="${REPO_ROOT}/examples/safe-demo/sample-repo"
SECCOMP_PROFILE="${REPO_ROOT}/apps/worker/seccomp-profile.json"
EVIDENCE_FILE="${REPO_ROOT}/reports/linux-docker-evidence.json"

mkdir -p "${REPO_ROOT}/reports"

echo "=== [1/6] Building ${IMAGE_TAG} from apps/worker/Dockerfile ==="
docker build -t "${IMAGE_TAG}" -f "${REPO_ROOT}/apps/worker/Dockerfile" "${REPO_ROOT}"

COMMON_FLAGS=(
  --rm
  --init
  --network=none
  --user=65532:65532
  --read-only
  --cap-drop=ALL
  --security-opt=no-new-privileges:true
  "--security-opt=seccomp=${SECCOMP_PROFILE}"
  --cpus=1.0
  --memory=536870912
  --memory-swap=536870912
  --pids-limit=64
  --mount "type=bind,src=${SAMPLE_REPO},dst=/workspace/target-repo,readonly"
  --tmpfs "/tmp/hegosentinel-scratch:rw,nosuid,nodev,noexec,size=67108864"
)

run_and_assert_container_probe() {
  local gate_id="$1"
  local expected_marker="$2"
  local node_script="$3"

  local out_file err_file rc
  out_file="$(mktemp)"
  err_file="$(mktemp)"

  set +e
  docker run "${COMMON_FLAGS[@]}" "${IMAGE_TAG}" node -e "${node_script}" >"${out_file}" 2>"${err_file}"
  rc=$?
  set -e

  local stdout_val stderr_val
  stdout_val="$(cat "${out_file}")"
  stderr_val="$(cat "${err_file}")"
  rm -f "${out_file}" "${err_file}"

  # Never interpret Docker CLI / daemon / command errors (125, 126, 127) as security success
  if [[ "${rc}" -eq 125 || "${rc}" -eq 126 || "${rc}" -eq 127 ]]; then
    echo "[FAIL] ${gate_id}: Docker CLI error (exit=${rc}, stderr=${stderr_val})" >&2
    exit 1
  fi

  if [[ "${rc}" -ne 0 ]]; then
    echo "[FAIL] ${gate_id}: Probe script failed inside container (exit=${rc}, stdout=${stdout_val}, stderr=${stderr_val})" >&2
    exit 1
  fi

  if [[ "${stdout_val}" != *"${expected_marker}"* ]]; then
    echo "[FAIL] ${gate_id}: Missing expected kernel verification marker '${expected_marker}' in stdout='${stdout_val}'" >&2
    exit 1
  fi

  echo "[PASS] ${gate_id}: exit=${rc} stdout=${stdout_val}" >&2
  printf '%s' "${stdout_val}"
}

echo "=== [2/6] WKR-001: Non-root 65532:65532, CapEff=0, NoNewPrivs=1 & --network=none internet block ==="
WKR001_OUT="$(run_and_assert_container_probe "WKR-001" "WKR001_VERIFIED" "
const fs = require('node:fs');
const net = require('node:net');
const uid = process.getuid();
const gid = process.getgid();
const status = fs.readFileSync('/proc/self/status', 'utf8');
const capEff = (status.match(/CapEff:\\s*([0-9a-f]+)/i) || [])[1] || '';
const noNewPrivs = (status.match(/NoNewPrivs:\\s*(\\d+)/i) || [])[1] || '';
if (uid !== 65532 || gid !== 65532 || capEff !== '0000000000000000' || noNewPrivs !== '1') {
  console.error('Identity/capability check failed', { uid, gid, capEff, noNewPrivs });
  process.exit(2);
}
const sock = net.connect({ host: '93.184.216.34', port: 443, timeout: 1500 });
sock.on('connect', () => { console.error('Unexpected internet connect'); process.exit(3); });
sock.on('error', (err) => {
  console.log('WKR001_VERIFIED uid=' + uid + ' gid=' + gid + ' capEff=' + capEff + ' noNewPrivs=' + noNewPrivs + ' netErr=' + err.code);
  process.exit(0);
});
")"

echo "=== [3/6] WKR-002: Cloud metadata 169.254.169.254 blocked & no /var/run/docker.sock mounted ==="
WKR002_OUT="$(run_and_assert_container_probe "WKR-002" "WKR002_VERIFIED" "
const fs = require('node:fs');
const net = require('node:net');
if (fs.existsSync('/var/run/docker.sock')) {
  console.error('docker.sock is mounted inside worker');
  process.exit(2);
}
const sock = net.connect({ host: '169.254.169.254', port: 80, timeout: 1500 });
sock.on('connect', () => { console.error('Metadata reachable'); process.exit(3); });
sock.on('error', (err) => {
  console.log('WKR002_VERIFIED dockerSock=absent metadataErr=' + err.code);
  process.exit(0);
});
")"

echo "=== [4/6] WKR-003: Read-only rootfs & /workspace/target-repo:ro reject writes (EROFS) ==="
WKR003_OUT="$(run_and_assert_container_probe "WKR-003" "WKR003_VERIFIED" "
const fs = require('node:fs');
let rootErr = '';
let repoErr = '';
try { fs.writeFileSync('/escape-root', 'x'); } catch (e) { rootErr = e.code; }
try { fs.writeFileSync('/workspace/target-repo/escape-repo', 'x'); } catch (e) { repoErr = e.code; }
fs.writeFileSync('/tmp/hegosentinel-scratch/probe.txt', 'ok');
if (rootErr !== 'EROFS' || repoErr !== 'EROFS') {
  console.error('Expected EROFS', { rootErr, repoErr });
  process.exit(2);
}
console.log('WKR003_VERIFIED rootfs=' + rootErr + ' repo=' + repoErr + ' scratch=WRITABLE');
")"

echo "=== [5/6] WKR-004: Non-root 65532:65532 denied /etc/shadow & host path isolation ==="
WKR004_OUT="$(run_and_assert_container_probe "WKR-004" "WKR004_VERIFIED" "
const fs = require('node:fs');
let shadowErr = '';
try { fs.readFileSync('/etc/shadow', 'utf8'); } catch (e) { shadowErr = e.code; }
if (shadowErr !== 'EACCES' && shadowErr !== 'EPERM') {
  console.error('Unexpected /etc/shadow access result', shadowErr);
  process.exit(2);
}
console.log('WKR004_VERIFIED shadowErr=' + shadowErr);
")"

echo "=== [6/6] WKR-005: Cgroup v2 PID (64) and Memory (536870912) limits active ==="
WKR005_OUT="$(run_and_assert_container_probe "WKR-005" "WKR005_VERIFIED" "
const fs = require('node:fs');
const pidsMax = fs.existsSync('/sys/fs/cgroup/pids.max') ? fs.readFileSync('/sys/fs/cgroup/pids.max', 'utf8').trim() : 'unknown';
const memMax = fs.existsSync('/sys/fs/cgroup/memory.max') ? fs.readFileSync('/sys/fs/cgroup/memory.max', 'utf8').trim() : 'unknown';
if (pidsMax !== '64' || memMax !== '536870912') {
  console.error('Unexpected cgroup limits', { pidsMax, memMax });
  process.exit(2);
}
console.log('WKR005_VERIFIED pidsMax=' + pidsMax + ' memMax=' + memMax);
")"

DOCKER_VER="$(docker info --format '{{.ServerVersion}}')"
HOST_OS="$(uname -srm)"
EVIDENCE_FILE="${EVIDENCE_FILE}" \
DOCKER_VER="${DOCKER_VER}" \
HOST_OS="${HOST_OS}" \
IMAGE_TAG="${IMAGE_TAG}" \
WKR001_OUT="${WKR001_OUT}" \
WKR002_OUT="${WKR002_OUT}" \
WKR003_OUT="${WKR003_OUT}" \
WKR004_OUT="${WKR004_OUT}" \
WKR005_OUT="${WKR005_OUT}" \
node -e '
const fs = require("node:fs");
const doc = {
  verified_at: new Date().toISOString(),
  host_os: process.env.HOST_OS,
  docker_server_version: process.env.DOCKER_VER,
  image: process.env.IMAGE_TAG,
  results: {
    "WKR-001": { verdict: "PASS", stdout: (process.env.WKR001_OUT || "").trim() },
    "WKR-002": { verdict: "PASS", stdout: (process.env.WKR002_OUT || "").trim() },
    "WKR-003": { verdict: "PASS", stdout: (process.env.WKR003_OUT || "").trim() },
    "WKR-004": { verdict: "PASS", stdout: (process.env.WKR004_OUT || "").trim() },
    "WKR-005": { verdict: "PASS", stdout: (process.env.WKR005_OUT || "").trim() }
  }
};
fs.writeFileSync(process.env.EVIDENCE_FILE, JSON.stringify(doc, null, 2) + "\n", "utf8");
'

echo "[OK] Saved Linux Docker containment evidence to ${EVIDENCE_FILE}"
