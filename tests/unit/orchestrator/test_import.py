import pytest


def test_import_orchestrator() -> None:
    """Tests that the orchestrator package can be imported."""

    try:
        import pcap_tool.orchestrator  # noqa: F401
    except ImportError as e:  # pragma: no cover - simple import check
        pytest.fail(str(e))
