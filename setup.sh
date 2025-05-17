#!/usr/bin/env bash
# setup.sh  – runs ONCE while the container still has Internet

set -euo pipefail

echo "🔧 Installing OS packages…"
apt-get update -qq
apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    gcc \
    g++ \
    tshark          # required by PyShark

echo "🐍 Installing Python dependencies…"
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# (Optional) prove installs worked
python - <<'PY'
import sys, pytest, pyshark, pcapkit, pandas, json
print(json.dumps({"python": sys.version.split()[0],
                  "pytest": pytest.__version__}, indent=2))
PY
