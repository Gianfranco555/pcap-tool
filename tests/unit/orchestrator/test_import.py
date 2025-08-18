import pytest

def test_import_orchestrator():
    """
    Tests that the orchestrator package can be imported.
    """
    try:
        import pcap_tool.orchestrator
    except ImportError as e:
        pytest.fail(f"Failed to import orchestrator: {e}")
