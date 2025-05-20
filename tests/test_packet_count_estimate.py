import subprocess

from pcap_tool.parser.core import _estimate_total_packets


def _fake_run_factory(stdout: str):
    def _fake_run(cmd, text=True, capture_output=True, check=True):
        return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")
    return _fake_run


def test_estimate_suffix_k(monkeypatch, tmp_path):
    fake = _fake_run_factory("Number of packets: 14 k\n")
    monkeypatch.delenv("PCAP_TOOL_CAPINFOS_PATH", raising=False)
    monkeypatch.setattr(subprocess, "run", fake)
    result = _estimate_total_packets(tmp_path / "x.pcap")
    assert result == 14_000


def test_estimate_suffix_m(monkeypatch, tmp_path):
    fake = _fake_run_factory("Number of packets: 3M\n")
    monkeypatch.delenv("PCAP_TOOL_CAPINFOS_PATH", raising=False)
    monkeypatch.setattr(subprocess, "run", fake)
    result = _estimate_total_packets(tmp_path / "x.pcap")
    assert result == 3_000_000


def test_estimate_no_suffix(monkeypatch, tmp_path):
    fake = _fake_run_factory("Number of packets: 42\n")
    monkeypatch.delenv("PCAP_TOOL_CAPINFOS_PATH", raising=False)
    monkeypatch.setattr(subprocess, "run", fake)
    result = _estimate_total_packets(tmp_path / "x.pcap")
    assert result == 42
