import sys
import types

# Define minimal stub for geoip2
class AddressNotFoundError(Exception):
    pass

class FakeCityRecord:
    def __init__(self):
        self.country = types.SimpleNamespace(name="Testland")
        self.city = types.SimpleNamespace(name="Exampleville")
        self.location = types.SimpleNamespace(latitude=1.23, longitude=4.56)

class FakeReader:
    def __init__(self, path):
        self.path = path

    def city(self, ip):
        if ip == "1.2.3.4":
            return FakeCityRecord()
        raise AddressNotFoundError("not found")


class FakeASNRecord:
    def __init__(self):
        self.autonomous_system_number = 12345
        self.autonomous_system_organization = "TestOrg"


class FakeASNReader:
    def __init__(self, path):
        self.path = path

    def asn(self, ip):
        if ip == "1.2.3.4":
            return FakeASNRecord()
        raise AddressNotFoundError("not found")

class FakeCountryRecord:
    def __init__(self, code="TL"):
        self.country = types.SimpleNamespace(iso_code=code)


class FakeCountryReader:
    def __init__(self, path):
        self.path = path

    def country(self, ip):
        if ip == "1.2.3.4":
            return FakeCountryRecord("TL")
        raise AddressNotFoundError("not found")

geoip2_mod = types.ModuleType("geoip2")
database_mod = types.ModuleType("geoip2.database")
errors_mod = types.ModuleType("geoip2.errors")

database_mod.Reader = FakeReader
errors_mod.AddressNotFoundError = AddressNotFoundError

database_mod.__dict__["AddressNotFoundError"] = AddressNotFoundError

geoip2_mod.database = database_mod
geoip2_mod.errors = errors_mod

sys.modules.setdefault("geoip2", geoip2_mod)
sys.modules.setdefault("geoip2.database", database_mod)
sys.modules.setdefault("geoip2.errors", errors_mod)

import importlib
import geoip2.database
import pcap_tool.enrichment as enrichment_mod
enrichment_mod = importlib.reload(enrichment_mod)
from pcap_tool.enrichment import Enricher


def test_get_geoip_no_db():
    enricher = Enricher()
    assert enricher.get_geoip("8.8.8.8") is None


def test_get_geoip_with_reader(monkeypatch):
    monkeypatch.setattr(geoip2.database, "Reader", lambda p: FakeReader(p))
    enricher = Enricher(geoip_city_db_path="dummy.mmdb")
    result = enricher.get_geoip("1.2.3.4")
    assert result == {
        "country": "Testland",
        "city": "Exampleville",
        "latitude": 1.23,
        "longitude": 4.56,
    }
    assert enricher.get_geoip("9.9.9.9") is None


def test_enrich_ips_includes_geo(monkeypatch):
    monkeypatch.setattr(geoip2.database, "Reader", lambda p: FakeReader(p))
    enricher = Enricher(geoip_city_db_path="dummy.mmdb")
    info = enricher.enrich_ips(["1.2.3.4"])
    assert info["1.2.3.4"]["geo"]["country"] == "Testland"


def test_get_asn_no_db():
    enricher = Enricher()
    assert enricher.get_asn("8.8.8.8") is None


def test_get_asn_with_reader(monkeypatch):
    monkeypatch.setattr(enrichment_mod, "Reader", FakeASNReader)
    monkeypatch.setattr(geoip2.database, "Reader", FakeASNReader)
    enricher = Enricher(geoip_asn_db_path="dummy.mmdb")
    result = enricher.get_asn("1.2.3.4")
    assert result == {"number": 12345, "organization": "TestOrg"}
    assert enricher.get_asn("9.9.9.9") is None


def test_enrich_ips_includes_asn(monkeypatch):
    monkeypatch.setattr(enrichment_mod, "Reader", FakeASNReader)
    monkeypatch.setattr(geoip2.database, "Reader", FakeASNReader)
    enricher = Enricher(geoip_asn_db_path="dummy.mmdb")
    info = enricher.enrich_ips(["1.2.3.4"])
    assert info["1.2.3.4"]["asn"]["organization"] == "TestOrg"


def test_get_rdns_caching(monkeypatch):
    calls = []

    def fake_gethostbyaddr(ip):
        calls.append(ip)
        return ("dns.google", [], [ip])

    monkeypatch.setattr(enrichment_mod.socket, "gethostbyaddr", fake_gethostbyaddr)
    enricher = Enricher()

    assert enricher.get_rdns("8.8.8.8") == "dns.google"
    assert enricher.get_rdns("8.8.8.8") == "dns.google"
    assert calls == ["8.8.8.8"]


def test_enrich_ips_rdns_cache(monkeypatch):
    count = {"n": 0}

    def fake_gethostbyaddr(ip):
        count["n"] += 1
        return ("dns.google", [], [ip])

    monkeypatch.setattr(enrichment_mod.socket, "gethostbyaddr", fake_gethostbyaddr)
    enricher = Enricher()

    first = enricher.enrich_ips(["8.8.8.8"])
    second = enricher.enrich_ips(["8.8.8.8"])

    assert first["8.8.8.8"]["rdns"] == "dns.google"
    assert second["8.8.8.8"]["rdns"] == "dns.google"
    assert count["n"] == 1


def test_get_country_with_reader(monkeypatch):
    monkeypatch.setattr(enrichment_mod, "Reader", FakeCountryReader)
    monkeypatch.setattr(geoip2.database, "Reader", lambda p: FakeCountryReader(p))
    enricher = Enricher(geoip_country_db_path="dummy.mmdb")
    assert enricher.get_country("1.2.3.4") == "TL"
    assert enricher.get_country("9.9.9.9") is None


def test_get_country_caching(monkeypatch):
    calls = {"n": 0}

    class CountingReader(FakeCountryReader):
        def country(self, ip):
            calls["n"] += 1
            return super().country(ip)

    monkeypatch.setattr(enrichment_mod, "Reader", CountingReader)
    monkeypatch.setattr(geoip2.database, "Reader", lambda p: CountingReader(p))
    enricher = Enricher(geoip_country_db_path="dummy.mmdb")
    assert enricher.get_country("1.2.3.4") == "TL"
    assert enricher.get_country("1.2.3.4") == "TL"
    assert calls["n"] == 1
