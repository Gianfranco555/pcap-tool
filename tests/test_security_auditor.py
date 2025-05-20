import pandas as pd

from pcap_tool.analyze.security_auditor import SecurityAuditor


class FakeEnricher:
    def __init__(self, mapping):
        self.mapping = mapping

    def enrich_ips(self, ips):
        return {ip: self.mapping.get(ip, {"geo": {"country": "USA"}}) for ip in ips}

    def get_country(self, ip):
        return self.mapping.get(ip, {}).get("country_code", "US")


def test_audit_flows_basic():
    df = pd.DataFrame(
        {
            "flow_id": ["1", "2", "3", "4"],
            "destination_ip": ["8.8.8.8", "3.3.3.3", "5.5.5.5", "6.6.6.6"],
            "security_flag_plaintext_http": [True, False, False, False],
            "security_flag_self_signed_cert": [False, True, False, False],
            "security_flag_outdated_tls_version": [pd.NA, "TLS 1.0", pd.NA, "TLS 1.1"],
        }
    )

    enricher = FakeEnricher({"3.3.3.3": {"geo": {"country": "Iran"}, "country_code": "IR"}})
    auditor = SecurityAuditor(enricher)
    result = auditor.audit_flows(df, ["8.8.8.8", "3.3.3.3", "5.5.5.5", "6.6.6.6"])

    assert result["plaintext_http_flows"] == 1
    assert result["self_signed_certificate_flows"] == 1
    assert result["outdated_tls_version_counts"] == {"TLS 1.0": 1, "TLS 1.1": 1}
    assert result["connections_to_unusual_countries"] == {"2": "IR"}
