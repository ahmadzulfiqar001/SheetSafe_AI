#!/usr/bin/env bash
# Reviewed, narrowly scoped operator smoke launcher for SheetSafe AI.
#
# SECURITY BOUNDARIES:
# - Must be executed ONLY as the dedicated 'sheetsafe-runner' broker account
#   (e.g. via: sudo -u sheetsafe-runner -- /path/to/scripts/run_operator_smoke.sh --dry-run).
# - Never runs as root (UID 0), container guest (UID 10001), or API/UI/validator accounts.
# - Never grants Docker socket access to sheetsafe-api, sheetsafe-ui, or sheetsafe-validator.
# - Uses only the protected state ledger at /var/lib/sheetsafe/runner/smoke_state.json.
# - Accepts ONLY --dry-run (default), --init-ledger, or --execute-approved-native-smoke.
# - Preserves execution_enabled=False and production_authorized=False.

set -euo pipefail
umask 0077

unset PYTHONPATH PYTHONSTARTUP PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH
unset DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG BASH_ENV ENV
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export LC_ALL="C.UTF-8"

EXPECTED_ACCOUNT="sheetsafe-runner"
PROTECTED_DIR="/var/lib/sheetsafe/runner"
STATE_FILE="/var/lib/sheetsafe/runner/smoke_state.json"

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "ERROR: Operator smoke launcher requires a native Linux host." >&2
    exit 2
fi

CURRENT_UID="$(id -u)"
CURRENT_GID="$(id -g)"
CURRENT_USER="$(id -un)"

if [[ "${CURRENT_UID}" -eq 0 ]] || [[ "${CURRENT_GID}" -eq 0 ]]; then
    echo "ERROR: Operator smoke launcher must not run as root (UID/GID 0)." >&2
    exit 2
fi

if [[ "${CURRENT_UID}" -eq 10001 ]] || [[ "${CURRENT_GID}" -eq 10001 ]]; then
    echo "ERROR: Operator smoke launcher must not run as container guest identity (10001:10001)." >&2
    exit 2
fi

if [[ "${CURRENT_USER}" != "${EXPECTED_ACCOUNT}" ]]; then
    echo "ERROR: Operator smoke launcher must run as '${EXPECTED_ACCOUNT}' (current: '${CURRENT_USER}')." >&2
    echo "Invoke via: sudo -u ${EXPECTED_ACCOUNT} -- $0 [--dry-run|--init-ledger|--execute-approved-native-smoke]" >&2
    exit 2
fi

if [[ -L "${PROTECTED_DIR}" ]] || [[ ! -d "${PROTECTED_DIR}" ]]; then
    echo "ERROR: Protected state directory ${PROTECTED_DIR} is missing or is a symlink." >&2
    exit 2
fi

DIR_MODE="$(stat -c '%a' "${PROTECTED_DIR}")"
DIR_UID="$(stat -c '%u' "${PROTECTED_DIR}")"
DIR_GID="$(stat -c '%g' "${PROTECTED_DIR}")"

if [[ "${DIR_MODE}" != "700" ]] || [[ "${DIR_UID}" != "${CURRENT_UID}" ]] || [[ "${DIR_GID}" != "${CURRENT_GID}" ]]; then
    echo "ERROR: ${PROTECTED_DIR} must be owned by ${CURRENT_UID}:${CURRENT_GID} with mode 700 (got ${DIR_UID}:${DIR_GID} mode ${DIR_MODE})." >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd -P)"

PYTHON_BIN="${SHEETSAFE_OPERATOR_PYTHON:-python3}"
if [[ "${PYTHON_BIN}" != "python3" ]]; then
    if [[ ! -x "${PYTHON_BIN}" ]] || [[ -L "${PYTHON_BIN}" ]]; then
        echo "ERROR: Invalid SHEETSAFE_OPERATOR_PYTHON binary." >&2
        exit 2
    fi
fi

MODE="${1:---dry-run}"
if [[ $# -gt 1 ]]; then
    echo "ERROR: Too many arguments. Usage: $0 [--dry-run|--init-ledger|--execute-approved-native-smoke]" >&2
    exit 2
fi

cd "${REPO_ROOT}"

case "${MODE}" in
    --init-ledger)
        exec "${PYTHON_BIN}" -m runner.smoke_adapter \
            --init-state-ledger \
            --verify-operator-deployment \
            --state-file "${STATE_FILE}"
        ;;
    --dry-run)
        exec "${PYTHON_BIN}" -m runner.smoke_adapter \
            --dry-run \
            --verify-operator-deployment \
            --context default \
            --fixture smoke-v1 \
            --state-file "${STATE_FILE}"
        ;;
    --execute-approved-native-smoke)
        exec "${PYTHON_BIN}" -m runner.smoke_adapter \
            --execute-approved-native-smoke \
            --verify-operator-deployment \
            --context default \
            --fixture smoke-v1 \
            --state-file "${STATE_FILE}"
        ;;
    *)
        echo "ERROR: Unsupported mode '${MODE}'. Allowed: --dry-run, --init-ledger, --execute-approved-native-smoke" >&2
        exit 2
        ;;
esac

