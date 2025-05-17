# AGENTS.md
# ------------------------------------------------------------------
# Configuration file for ChatGPT + Codex agents
# ------------------------------------------------------------------
# Anything under `setup:` runs **once**, while the container still has
# outbound network.  After the last setup command, all Internet access
# is disabled.  From that point on, the agent can only run the `test`
# and optional `lint` commands you define below.
# ------------------------------------------------------------------

setup: |
  # --- OS packages -------------------------------------------------
  apt-get update -qq
  apt-get install -y --no-install-recommends \
      build-essential \
      python3-dev \
      gcc \
      g++ \
      tshark         # required by PyShark

  # --- Python tooling ----------------------------------------------
  python -m pip install --upgrade pip
  # Install project dependencies *from requirements.txt*.
  # (Add --no-cache-dir if you want smaller containers.)
  python -m pip install -r requirements.txt

  # --- Environment tweaks ------------------------------------------
  # Tell PyShark exactly where tshark lives (optional—usually not needed
  # because we installed it system-wide, but explicit is better).
  export TSHARK_PATH="$(command -v tshark)"

test: |
  # Run the full pytest suite quietly (dots only)
  pytest -q

# Optional.  Uncomment if you want Codex to lint before patch proposals.
# lint: |
#   python -m pip install flake8
#   flake8 src tests

# Optional.  If your codebase needs a particular working directory,
# specify it here; otherwise the agent uses repo root by default.
# workdir: "/workspace/pcap-tool"
