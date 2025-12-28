"""Unit tests for helper_functions.enrichment.

These tests validate enrichment functions by using normalized data files
from the example_data/ directory.
"""

import pytest
import json
import os
from helper_functions.enrichment import (
    enrich_abuseipdb,
    enrich_ipinfo,
    enrich_ip_virustotal,
    enrich_domain_virustotal,
    enrich_file_hash_virustotal,
    enrich_ip_alienvault,
    enrich_domain_alienvault,
    combined_enrichment,
)


# Fixture paths
EXAMPLE_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "example_data")


@pytest.fixture
def abuseipdb_normalized_data():
    """Load normalized AbuseIPDB data from example file."""
    with open(os.path.join(EXAMPLE_DATA_DIR, "normalized_abuseipdb.json"), "r") as f:
        return json.load(f)


@pytest.fixture
def ipinfo_normalized_data():
    """Load normalized ipinfo.io data from example file."""
    with open(os.path.join(EXAMPLE_DATA_DIR, "normalized_ipinfo.json"), "r") as f:
        return json.load(f)


@pytest.fixture
def ip_virustotal_normalized_data():
    """Load normalized VirusTotal IP data from example file."""
    with open(
        os.path.join(EXAMPLE_DATA_DIR, "normalized_ip_virustotal.json"), "r"
    ) as f:
        return json.load(f)


@pytest.fixture
def file_hash_virustotal_normalized_data():
    """Load normalized VirusTotal file hash data from example file."""
    with open(
        os.path.join(EXAMPLE_DATA_DIR, "normalized_file_hash_virustotal.json"), "r"
    ) as f:
        return json.load(f)


@pytest.fixture
def domain_virustotal_normalized_data():
    """Load normalized VirusTotal domain data from example file."""
    with open(
        os.path.join(EXAMPLE_DATA_DIR, "normalized_domain_virustotal.json"), "r"
    ) as f:
        return json.load(f)


@pytest.fixture
def ip_alienvault_normalized_data():
    """Load normalized AlienVault IP data from example file."""
    with open(
        os.path.join(EXAMPLE_DATA_DIR, "normalized_ip_alienvault.json"), "r"
    ) as f:
        return json.load(f)


@pytest.fixture
def domain_alienvault_normalized_data():
    """Load normalized AlienVault domain data from example file."""
    with open(
        os.path.join(EXAMPLE_DATA_DIR, "normalized_domain_alienvault.json"), "r"
    ) as f:
        return json.load(f)


class TestEnrichAbuseIPDB:
    """Test suite for AbuseIPDB enrichment."""

    def test_enrich_abuseipdb_returns_string(self, abuseipdb_normalized_data):
        """Test that enrich_abuseipdb returns a string."""
        result = enrich_abuseipdb(abuseipdb_normalized_data)
        assert isinstance(result, str)

    def test_enrich_abuseipdb_contains_analyzed_time(self, abuseipdb_normalized_data):
        """Test that enrichment contains analyzed time."""
        result = enrich_abuseipdb(abuseipdb_normalized_data)
        assert "Analyzed at:" in result

    def test_enrich_abuseipdb_contains_link(self, abuseipdb_normalized_data):
        """Test that enrichment contains AbuseIPDB link."""
        result = enrich_abuseipdb(abuseipdb_normalized_data)
        assert "AbuseIPDB Link:" in result
        assert "abuseipdb.com" in result

    def test_enrich_abuseipdb_contains_defanged_ip(self, abuseipdb_normalized_data):
        """Test that enrichment contains defanged IP."""
        result = enrich_abuseipdb(abuseipdb_normalized_data)
        assert "Defanged IP:" in result
        assert "[.]" in result

    def test_enrich_abuseipdb_contains_status(self, abuseipdb_normalized_data):
        """Test that enrichment contains status (Malicious or Clean)."""
        result = enrich_abuseipdb(abuseipdb_normalized_data)
        assert "Status:" in result
        assert "Malicious" in result or "Clean" in result

    def test_enrich_abuseipdb_contains_confidence_score(
        self, abuseipdb_normalized_data
    ):
        """Test that enrichment contains abuse confidence score."""
        result = enrich_abuseipdb(abuseipdb_normalized_data)
        assert "Abuse Confidence Score:" in result

    def test_enrich_abuseipdb_contains_report_info(self, abuseipdb_normalized_data):
        """Test that enrichment contains report information."""
        result = enrich_abuseipdb(abuseipdb_normalized_data)
        if abuseipdb_normalized_data.get("abuse_info"):
            assert "Total Reports:" in result

    def test_enrich_abuseipdb_contains_geo_info(self, abuseipdb_normalized_data):
        """Test that enrichment contains geographic information."""
        result = enrich_abuseipdb(abuseipdb_normalized_data)
        if abuseipdb_normalized_data.get("geo_info"):
            assert "Country:" in result

    def test_enrich_abuseipdb_contains_network_info(self, abuseipdb_normalized_data):
        """Test that enrichment contains network information."""
        result = enrich_abuseipdb(abuseipdb_normalized_data)
        if abuseipdb_normalized_data.get("network_info"):
            assert "ISP:" in result

    def test_enrich_abuseipdb_not_empty(self, abuseipdb_normalized_data):
        """Test that enrichment result is not empty."""
        result = enrich_abuseipdb(abuseipdb_normalized_data)
        assert len(result) > 0


class TestEnrichIPInfo:
    """Test suite for ipinfo.io enrichment."""

    def test_enrich_ipinfo_returns_string(self, ipinfo_normalized_data):
        """Test that enrich_ipinfo returns a string."""
        result = enrich_ipinfo(ipinfo_normalized_data)
        assert isinstance(result, str)

    def test_enrich_ipinfo_contains_analyzed_time(self, ipinfo_normalized_data):
        """Test that enrichment contains analyzed time."""
        result = enrich_ipinfo(ipinfo_normalized_data)
        assert "Analyzed at:" in result

    def test_enrich_ipinfo_contains_link(self, ipinfo_normalized_data):
        """Test that enrichment contains ipinfo.io link."""
        result = enrich_ipinfo(ipinfo_normalized_data)
        assert "ipinfo.io Link:" in result
        assert "ipinfo.io" in result

    def test_enrich_ipinfo_contains_defanged_ip(self, ipinfo_normalized_data):
        """Test that enrichment contains defanged IP."""
        result = enrich_ipinfo(ipinfo_normalized_data)
        assert "Defanged IP:" in result
        assert "[.]" in result

    def test_enrich_ipinfo_contains_location(self, ipinfo_normalized_data):
        """Test that enrichment contains location information."""
        result = enrich_ipinfo(ipinfo_normalized_data)
        if ipinfo_normalized_data.get("geo_info"):
            assert "Location:" in result

    def test_enrich_ipinfo_contains_coordinates(self, ipinfo_normalized_data):
        """Test that enrichment contains coordinates."""
        result = enrich_ipinfo(ipinfo_normalized_data)
        if ipinfo_normalized_data.get("geo_info"):
            assert "Coordinates:" in result

    def test_enrich_ipinfo_contains_timezone(self, ipinfo_normalized_data):
        """Test that enrichment contains timezone."""
        result = enrich_ipinfo(ipinfo_normalized_data)
        if ipinfo_normalized_data.get("geo_info"):
            assert "Timezone:" in result

    def test_enrich_ipinfo_contains_asn(self, ipinfo_normalized_data):
        """Test that enrichment contains ASN information."""
        result = enrich_ipinfo(ipinfo_normalized_data)
        if ipinfo_normalized_data.get("network_info"):
            assert "ASN:" in result

    def test_enrich_ipinfo_contains_organization(self, ipinfo_normalized_data):
        """Test that enrichment contains organization information."""
        result = enrich_ipinfo(ipinfo_normalized_data)
        if ipinfo_normalized_data.get("network_info"):
            assert "Organization:" in result

    def test_enrich_ipinfo_not_empty(self, ipinfo_normalized_data):
        """Test that enrichment result is not empty."""
        result = enrich_ipinfo(ipinfo_normalized_data)
        assert len(result) > 0


class TestEnrichIPVirusTotal:
    """Test suite for VirusTotal IP enrichment."""

    def test_enrich_ip_virustotal_returns_string(self, ip_virustotal_normalized_data):
        """Test that enrich_ip_virustotal returns a string."""
        result = enrich_ip_virustotal(ip_virustotal_normalized_data)
        assert isinstance(result, str)

    def test_enrich_ip_virustotal_contains_analyzed_time(
        self, ip_virustotal_normalized_data
    ):
        """Test that enrichment contains analyzed time."""
        result = enrich_ip_virustotal(ip_virustotal_normalized_data)
        assert "Analyzed at:" in result

    def test_enrich_ip_virustotal_contains_link(self, ip_virustotal_normalized_data):
        """Test that enrichment contains VirusTotal link."""
        result = enrich_ip_virustotal(ip_virustotal_normalized_data)
        assert "VirusTotal Link:" in result
        assert "virustotal.com" in result

    def test_enrich_ip_virustotal_contains_defanged_ip(
        self, ip_virustotal_normalized_data
    ):
        """Test that enrichment contains defanged IP."""
        result = enrich_ip_virustotal(ip_virustotal_normalized_data)
        assert "Defanged IP:" in result
        assert "[.]" in result

    def test_enrich_ip_virustotal_contains_status(self, ip_virustotal_normalized_data):
        """Test that enrichment contains status."""
        result = enrich_ip_virustotal(ip_virustotal_normalized_data)
        assert "Status:" in result

    def test_enrich_ip_virustotal_contains_detection_stats(
        self, ip_virustotal_normalized_data
    ):
        """Test that enrichment contains detection statistics."""
        result = enrich_ip_virustotal(ip_virustotal_normalized_data)
        if ip_virustotal_normalized_data.get("detection_stats"):
            assert "Detection:" in result

    def test_enrich_ip_virustotal_not_empty(self, ip_virustotal_normalized_data):
        """Test that enrichment result is not empty."""
        result = enrich_ip_virustotal(ip_virustotal_normalized_data)
        assert len(result) > 0


class TestEnrichDomainVirusTotal:
    """Test suite for VirusTotal domain enrichment."""

    def test_enrich_domain_virustotal_returns_string(
        self, domain_virustotal_normalized_data
    ):
        """Test that enrich_domain_virustotal returns a string."""
        result = enrich_domain_virustotal(domain_virustotal_normalized_data)
        assert isinstance(result, str)

    def test_enrich_domain_virustotal_contains_analyzed_time(
        self, domain_virustotal_normalized_data
    ):
        """Test that enrichment contains analyzed time."""
        result = enrich_domain_virustotal(domain_virustotal_normalized_data)
        assert "Analyzed at:" in result

    def test_enrich_domain_virustotal_contains_link(
        self, domain_virustotal_normalized_data
    ):
        """Test that enrichment contains VirusTotal link."""
        result = enrich_domain_virustotal(domain_virustotal_normalized_data)
        assert "VirusTotal Link:" in result
        assert "virustotal.com" in result

    def test_enrich_domain_virustotal_contains_defanged_domain(
        self, domain_virustotal_normalized_data
    ):
        """Test that enrichment contains defanged domain."""
        result = enrich_domain_virustotal(domain_virustotal_normalized_data)
        assert "Defanged Domain:" in result
        assert "[.]" in result

    def test_enrich_domain_virustotal_contains_status(
        self, domain_virustotal_normalized_data
    ):
        """Test that enrichment contains status."""
        result = enrich_domain_virustotal(domain_virustotal_normalized_data)
        assert "Status:" in result

    def test_enrich_domain_virustotal_contains_detection_stats(
        self, domain_virustotal_normalized_data
    ):
        """Test that enrichment contains detection statistics."""
        result = enrich_domain_virustotal(domain_virustotal_normalized_data)
        if domain_virustotal_normalized_data.get("detection_stats"):
            assert "Detection:" in result

    def test_enrich_domain_virustotal_not_empty(
        self, domain_virustotal_normalized_data
    ):
        """Test that enrichment result is not empty."""
        result = enrich_domain_virustotal(domain_virustotal_normalized_data)
        assert len(result) > 0


class TestEnrichFileHashVirusTotal:
    """Test suite for VirusTotal file hash enrichment."""

    def test_enrich_file_hash_virustotal_returns_string(
        self, file_hash_virustotal_normalized_data
    ):
        """Test that enrich_file_hash_virustotal returns a string."""
        result = enrich_file_hash_virustotal(file_hash_virustotal_normalized_data)
        assert isinstance(result, str)

    def test_enrich_file_hash_virustotal_contains_analyzed_time(
        self, file_hash_virustotal_normalized_data
    ):
        """Test that enrichment contains analyzed time."""
        result = enrich_file_hash_virustotal(file_hash_virustotal_normalized_data)
        assert "Analyzed at:" in result

    def test_enrich_file_hash_virustotal_contains_link(
        self, file_hash_virustotal_normalized_data
    ):
        """Test that enrichment contains VirusTotal link."""
        result = enrich_file_hash_virustotal(file_hash_virustotal_normalized_data)
        assert "VirusTotal Link:" in result
        assert "virustotal.com" in result

    def test_enrich_file_hash_virustotal_contains_hashes(
        self, file_hash_virustotal_normalized_data
    ):
        """Test that enrichment contains file hashes."""
        result = enrich_file_hash_virustotal(file_hash_virustotal_normalized_data)
        # File hash enrichment includes MD5, SHA1, SHA256 but not a 'File Hash:' label
        assert "MD5:" in result or "SHA1:" in result or "SHA256:" in result

    def test_enrich_file_hash_virustotal_contains_status(
        self, file_hash_virustotal_normalized_data
    ):
        """Test that enrichment contains status."""
        result = enrich_file_hash_virustotal(file_hash_virustotal_normalized_data)
        assert "Status:" in result

    def test_enrich_file_hash_virustotal_contains_detection_stats(
        self, file_hash_virustotal_normalized_data
    ):
        """Test that enrichment contains detection statistics."""
        result = enrich_file_hash_virustotal(file_hash_virustotal_normalized_data)
        if file_hash_virustotal_normalized_data.get("detection_stats"):
            assert "Detection:" in result

    def test_enrich_file_hash_virustotal_contains_file_info(
        self, file_hash_virustotal_normalized_data
    ):
        """Test that enrichment contains file information."""
        result = enrich_file_hash_virustotal(file_hash_virustotal_normalized_data)
        if file_hash_virustotal_normalized_data.get("file_info"):
            assert "File Type:" in result or "File Size:" in result

    def test_enrich_file_hash_virustotal_not_empty(
        self, file_hash_virustotal_normalized_data
    ):
        """Test that enrichment result is not empty."""
        result = enrich_file_hash_virustotal(file_hash_virustotal_normalized_data)
        assert len(result) > 0


class TestEnrichIPAlienVault:
    """Test suite for AlienVault IP enrichment."""

    def test_enrich_ip_alienvault_returns_string(self, ip_alienvault_normalized_data):
        """Test that enrich_ip_alienvault returns a string."""
        result = enrich_ip_alienvault(ip_alienvault_normalized_data)
        assert isinstance(result, str)

    def test_enrich_ip_alienvault_contains_analyzed_time(
        self, ip_alienvault_normalized_data
    ):
        """Test that enrichment contains analyzed time."""
        result = enrich_ip_alienvault(ip_alienvault_normalized_data)
        assert "Analyzed at:" in result

    def test_enrich_ip_alienvault_contains_defanged_ip(
        self, ip_alienvault_normalized_data
    ):
        """Test that enrichment contains defanged IP."""
        result = enrich_ip_alienvault(ip_alienvault_normalized_data)
        assert "Defanged IP:" in result
        assert "[.]" in result

    def test_enrich_ip_alienvault_contains_status(self, ip_alienvault_normalized_data):
        """Test that enrichment contains status."""
        result = enrich_ip_alienvault(ip_alienvault_normalized_data)
        assert "Status:" in result

    def test_enrich_ip_alienvault_contains_pulse_count(
        self, ip_alienvault_normalized_data
    ):
        """Test that enrichment contains pulse count."""
        result = enrich_ip_alienvault(ip_alienvault_normalized_data)
        if ip_alienvault_normalized_data.get("abuse_info"):
            assert "Pulse Count:" in result

    def test_enrich_ip_alienvault_not_empty(self, ip_alienvault_normalized_data):
        """Test that enrichment result is not empty."""
        result = enrich_ip_alienvault(ip_alienvault_normalized_data)
        assert len(result) > 0


class TestEnrichDomainAlienVault:
    """Test suite for AlienVault domain enrichment."""

    def test_enrich_domain_alienvault_returns_string(
        self, domain_alienvault_normalized_data
    ):
        """Test that enrich_domain_alienvault returns a string."""
        result = enrich_domain_alienvault(domain_alienvault_normalized_data)
        assert isinstance(result, str)

    def test_enrich_domain_alienvault_contains_analyzed_time(
        self, domain_alienvault_normalized_data
    ):
        """Test that enrichment contains analyzed time."""
        result = enrich_domain_alienvault(domain_alienvault_normalized_data)
        assert "Analyzed at:" in result

    def test_enrich_domain_alienvault_contains_link(
        self, domain_alienvault_normalized_data
    ):
        """Test that enrichment contains AlienVault link."""
        result = enrich_domain_alienvault(domain_alienvault_normalized_data)
        assert "AlienVault OTX Link:" in result
        assert "otx.alienvault.com" in result

    def test_enrich_domain_alienvault_contains_defanged_domain(
        self, domain_alienvault_normalized_data
    ):
        """Test that enrichment contains defanged domain."""
        result = enrich_domain_alienvault(domain_alienvault_normalized_data)
        assert "Defanged Domain:" in result
        assert "[.]" in result

    def test_enrich_domain_alienvault_contains_status(
        self, domain_alienvault_normalized_data
    ):
        """Test that enrichment contains status."""
        result = enrich_domain_alienvault(domain_alienvault_normalized_data)
        assert "Status:" in result

    def test_enrich_domain_alienvault_contains_pulse_count(
        self, domain_alienvault_normalized_data
    ):
        """Test that enrichment contains pulse count."""
        result = enrich_domain_alienvault(domain_alienvault_normalized_data)
        if domain_alienvault_normalized_data.get("abuse_info"):
            assert "Pulse Count:" in result

    def test_enrich_domain_alienvault_not_empty(
        self, domain_alienvault_normalized_data
    ):
        """Test that enrichment result is not empty."""
        result = enrich_domain_alienvault(domain_alienvault_normalized_data)
        assert len(result) > 0


class TestCombinedEnrichment:
    """Test suite for combined enrichment functionality."""

    def test_combined_enrichment_returns_string(
        self,
        abuseipdb_normalized_data,
        ipinfo_normalized_data,
        ip_virustotal_normalized_data,
        domain_virustotal_normalized_data,
        file_hash_virustotal_normalized_data,
    ):
        """Test that combined_enrichment returns a string."""
        result = combined_enrichment(
            abuseipdb_data=abuseipdb_normalized_data,
            ipinfo_data=ipinfo_normalized_data,
            ip_virustotal_data=ip_virustotal_normalized_data,
            domain_virustotal_data=domain_virustotal_normalized_data,
            file_hash_virustotal_data=file_hash_virustotal_normalized_data,
        )
        assert isinstance(result, str)

    def test_combined_enrichment_contains_header(self, abuseipdb_normalized_data):
        """Test that combined enrichment contains summary header."""
        result = combined_enrichment(abuseipdb_data=abuseipdb_normalized_data)
        assert "That SOCs Enrichment Summary" in result

    def test_combined_enrichment_contains_abuseipdb_section(
        self, abuseipdb_normalized_data
    ):
        """Test that combined enrichment contains AbuseIPDB section when data provided."""
        result = combined_enrichment(abuseipdb_data=abuseipdb_normalized_data)
        assert "ABUSEIPDB ANALYSIS" in result

    def test_combined_enrichment_contains_ipinfo_section(self, ipinfo_normalized_data):
        """Test that combined enrichment contains ipinfo section when data provided."""
        result = combined_enrichment(ipinfo_data=ipinfo_normalized_data)
        assert "IPINFO.IO ANALYSIS" in result

    def test_combined_enrichment_contains_vt_ip_section(
        self, ip_virustotal_normalized_data
    ):
        """Test that combined enrichment contains VirusTotal IP section when data provided."""
        result = combined_enrichment(ip_virustotal_data=ip_virustotal_normalized_data)
        assert "VIRUSTOTAL IP ANALYSIS" in result

    def test_combined_enrichment_contains_vt_domain_section(
        self, domain_virustotal_normalized_data
    ):
        """Test that combined enrichment contains VirusTotal domain section when data provided."""
        result = combined_enrichment(
            domain_virustotal_data=domain_virustotal_normalized_data
        )
        assert "VIRUSTOTAL DOMAIN ANALYSIS" in result

    def test_combined_enrichment_contains_vt_file_section(
        self, file_hash_virustotal_normalized_data
    ):
        """Test that combined enrichment contains VirusTotal file hash section when data provided."""
        result = combined_enrichment(
            file_hash_virustotal_data=file_hash_virustotal_normalized_data
        )
        assert "VIRUSTOTAL FILE HASH ANALYSIS" in result

    def test_combined_enrichment_all_sources(
        self,
        abuseipdb_normalized_data,
        ipinfo_normalized_data,
        ip_virustotal_normalized_data,
        domain_virustotal_normalized_data,
        file_hash_virustotal_normalized_data,
        ip_alienvault_normalized_data,
        domain_alienvault_normalized_data,
    ):
        """Test that combined enrichment includes all sections when all data provided."""
        result = combined_enrichment(
            abuseipdb_data=abuseipdb_normalized_data,
            ipinfo_data=ipinfo_normalized_data,
            ip_virustotal_data=ip_virustotal_normalized_data,
            domain_virustotal_data=domain_virustotal_normalized_data,
            file_hash_virustotal_data=file_hash_virustotal_normalized_data,
            ip_alienvault_data=ip_alienvault_normalized_data,
            domain_alienvault_data=domain_alienvault_normalized_data,
        )
        assert "ABUSEIPDB ANALYSIS" in result
        assert "IPINFO.IO ANALYSIS" in result
        assert "VIRUSTOTAL IP ANALYSIS" in result
        assert "VIRUSTOTAL DOMAIN ANALYSIS" in result
        assert "VIRUSTOTAL FILE HASH ANALYSIS" in result
        assert "ALIENVAULT OTX IP ANALYSIS" in result
        assert "ALIENVAULT OTX DOMAIN ANALYSIS" in result

    def test_combined_enrichment_no_data(self):
        """Test that combined enrichment handles no data gracefully."""
        result = combined_enrichment()
        assert isinstance(result, str)
        assert "No threat intelligence data provided" in result

    def test_combined_enrichment_partial_data(
        self, abuseipdb_normalized_data, domain_virustotal_normalized_data
    ):
        """Test that combined enrichment works with partial data."""
        result = combined_enrichment(
            abuseipdb_data=abuseipdb_normalized_data,
            domain_virustotal_data=domain_virustotal_normalized_data,
        )
        assert "ABUSEIPDB ANALYSIS" in result
        assert "VIRUSTOTAL DOMAIN ANALYSIS" in result
        assert "IPINFO.IO ANALYSIS" not in result

    def test_combined_enrichment_contains_separators(
        self, abuseipdb_normalized_data, ipinfo_normalized_data
    ):
        """Test that combined enrichment contains section separators."""
        result = combined_enrichment(
            abuseipdb_data=abuseipdb_normalized_data,
            ipinfo_data=ipinfo_normalized_data,
        )
        # Check for separator lines (=== characters)
        assert "=" * 60 in result


class TestEnrichmentConsistency:
    """Test suite for consistency across enrichment functions."""

    def test_all_enrichments_return_strings(
        self,
        abuseipdb_normalized_data,
        ipinfo_normalized_data,
        ip_virustotal_normalized_data,
        domain_virustotal_normalized_data,
        file_hash_virustotal_normalized_data,
        ip_alienvault_normalized_data,
        domain_alienvault_normalized_data,
    ):
        """Test that all enrichment functions return strings."""
        results = [
            enrich_abuseipdb(abuseipdb_normalized_data),
            enrich_ipinfo(ipinfo_normalized_data),
            enrich_ip_virustotal(ip_virustotal_normalized_data),
            enrich_domain_virustotal(domain_virustotal_normalized_data),
            enrich_file_hash_virustotal(file_hash_virustotal_normalized_data),
            enrich_ip_alienvault(ip_alienvault_normalized_data),
            enrich_domain_alienvault(domain_alienvault_normalized_data),
        ]

        for result in results:
            assert isinstance(result, str)
            assert len(result) > 0

    def test_all_enrichments_contain_analyzed_time(
        self,
        abuseipdb_normalized_data,
        ipinfo_normalized_data,
        ip_virustotal_normalized_data,
        domain_virustotal_normalized_data,
        file_hash_virustotal_normalized_data,
        ip_alienvault_normalized_data,
        domain_alienvault_normalized_data,
    ):
        """Test that all enrichment functions include analyzed time."""
        results = [
            enrich_abuseipdb(abuseipdb_normalized_data),
            enrich_ipinfo(ipinfo_normalized_data),
            enrich_ip_virustotal(ip_virustotal_normalized_data),
            enrich_domain_virustotal(domain_virustotal_normalized_data),
            enrich_file_hash_virustotal(file_hash_virustotal_normalized_data),
            enrich_ip_alienvault(ip_alienvault_normalized_data),
            enrich_domain_alienvault(domain_alienvault_normalized_data),
        ]

        for result in results:
            assert "Analyzed at:" in result

    def test_all_enrichments_contain_links(
        self,
        abuseipdb_normalized_data,
        ipinfo_normalized_data,
        ip_virustotal_normalized_data,
        domain_virustotal_normalized_data,
        file_hash_virustotal_normalized_data,
        ip_alienvault_normalized_data,
        domain_alienvault_normalized_data,
    ):
        """Test that all enrichment functions include source links."""
        results = [
            (enrich_abuseipdb(abuseipdb_normalized_data), "abuseipdb.com"),
            (enrich_ipinfo(ipinfo_normalized_data), "ipinfo.io"),
            (enrich_ip_virustotal(ip_virustotal_normalized_data), "virustotal.com"),
            (
                enrich_domain_virustotal(domain_virustotal_normalized_data),
                "virustotal.com",
            ),
            (
                enrich_file_hash_virustotal(file_hash_virustotal_normalized_data),
                "virustotal.com",
            ),
            (enrich_ip_alienvault(ip_alienvault_normalized_data), "otx.alienvault.com"),
            (
                enrich_domain_alienvault(domain_alienvault_normalized_data),
                "otx.alienvault.com",
            ),
        ]

        for result, expected_domain in results:
            assert expected_domain in result

    def test_ip_enrichments_contain_defanged_ips(
        self,
        abuseipdb_normalized_data,
        ipinfo_normalized_data,
        ip_virustotal_normalized_data,
    ):
        """Test that IP enrichment functions include defanged IPs."""
        results = [
            enrich_abuseipdb(abuseipdb_normalized_data),
            enrich_ipinfo(ipinfo_normalized_data),
            enrich_ip_virustotal(ip_virustotal_normalized_data),
        ]

        for result in results:
            assert "[.]" in result  # Defanged IP indicator
