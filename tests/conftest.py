import sys
from pathlib import Path

# Ensure the src directory is on sys.path for test imports
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))


import pytest


@pytest.fixture
def example_pcap() -> Path:
    """Return path to a small example pcap for tests."""
    return PROJECT_ROOT / "tests" / "fixtures" / "mini.pcapng"
