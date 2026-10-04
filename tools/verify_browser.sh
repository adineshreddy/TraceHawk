#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
case "${1:-phase1}" in
 phase1) script=e2e.cjs ;;
 phase2) script=e2e-phase2.cjs ;;
 phase3) script=e2e-phase3.cjs ;;
 phase4) script=e2e-phase4.cjs ;;
 phase6) script=e2e-phase6.cjs ;;
 *) echo 'Usage: tools/verify_browser.sh [phase1|phase2|phase3|phase4|phase6]' >&2; exit 2 ;;
esac
docker run --rm --network tracehawk_public --ipc=host --memory=768m \
 -v "$PWD:/workspace" -w /workspace/services/console \
 mcr.microsoft.com/playwright:v1.63.0-noble@sha256:eff16c30e6f3f4af0a03fa4b706120d5e9b0891c344a27d64559aff5900a4a27 \
 node "$script"
