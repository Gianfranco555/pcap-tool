import pytest

def test_import_defrag():
    """Test that the defrag extra (scapy) can be imported."""
    pytest.importorskip("scapy")

def test_import_reassembly():
    """Test that the reassembly extra (pcapkit) can be imported."""
    pytest.importorskip("pypcapkit")
