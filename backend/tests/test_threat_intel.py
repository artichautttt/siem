"""
test_threat_intel.py — Vérifie le vrai appel réseau vers le flux externe
(contrairement à test_detector.py::test_known_bad_ip_detected, qui mocke
get_known_bad_ips pour rester rapide et déterministe).
"""
import threat_intel


def test_fetch_real_feed_returns_ips():
    threat_intel._cache.update(ips=None, fetched_at=0.0, source=None)  # force un fetch
    ips, source = threat_intel.get_known_bad_ips()
    assert len(ips) > 100  # le flux réel contient des dizaines de milliers d'IP
    assert source == threat_intel.THREAT_INTEL_URL
    # Format IPv4 basique sur un échantillon
    sample = next(iter(ips))
    assert sample.count(".") == 3


def test_cache_avoids_refetch(monkeypatch):
    calls = {"n": 0}

    def fake_get(*args, **kwargs):
        calls["n"] += 1
        raise AssertionError("ne devrait pas être appelé : le cache doit être servi")

    threat_intel._cache.update(ips={"1.2.3.4"}, fetched_at=__import__("time").time(), source="cached")
    monkeypatch.setattr(threat_intel.requests, "get", fake_get)

    ips, source = threat_intel.get_known_bad_ips()
    assert ips == {"1.2.3.4"}
    assert source == "cached"
    assert calls["n"] == 0


def test_fallback_on_network_error(monkeypatch):
    def fake_get(*args, **kwargs):
        raise threat_intel.requests.ConnectionError("réseau coupé (simulé)")

    threat_intel._cache.update(ips=None, fetched_at=0.0, source=None)
    monkeypatch.setattr(threat_intel.requests, "get", fake_get)

    ips, source = threat_intel.get_known_bad_ips()
    assert source == "static-fallback"
    assert ips == threat_intel.KNOWN_BAD_IPS_FALLBACK
