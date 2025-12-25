"""Thin wrappers for normalizing threat intelligence data from several Threat Intelligence sources into a common schema.

This module supports normalization for VirusTotal, AbuseIPDB and ipinfo.io threat intelligence data.
"""

from datetime import datetime, timezone
from helper_functions.logging_config import setup_logger

logger = setup_logger(
    name="normalize_threat_intelligence", log_file="that-socs.log"
)


# TODO: Fine tune schema as needed
class ThreatIntelligenceNormalizedSchema:
    """Common schema for normalized threat intelligence data.

    Attributes:
        # Metadata
        schema_version (str): Version of the normalization schema. Added for future backwards compatibility considerations.
        normalized_time (str): ISO 8601 timestamp when normalization was performed.

        # Core IOC Information
        source (str): Source of the threat intelligence data (e.g., 'VirusTotal', 'AbuseIPDB', 'ipinfo.io')
        ioc_type (str): Type of IOC ('ip', 'file_hash', 'domain', 'url')
        ioc (str): The actual IOC value

        # Threat Assessment
        reputation_score (int | None): Reputation score if available (source-specific scale)
        malicious (bool | None): Whether the IOC is considered malicious
        confidence_score (int | None): Confidence level in the assessment (0-100)

        # Detection Statistics
        detection_stats (dict | None): Analysis results summary
            - malicious: count of engines flagging as malicious
            - suspicious: count of engines flagging as suspicious
            - harmless: count of engines flagging as harmless
            - undetected: count of engines with no verdict
            - total: total number of engines

        # Geolocation Data (for IPs)
        geo_info (dict | None):
            - country: country code
            - country_name: full country name
            - city: city name
            - region: region/state
            - coordinates: lat/long coordinates
            - timezone: timezone

        # Network/Infrastructure Info
        network_info (dict | None):
            - asn: autonomous system number
            - isp: internet service provider
            - organization: organization name
            - hostnames: list of associated hostnames
            - domain: associated domain

        # Abuse/Threat Indicators
        abuse_info (dict | None):
            - abuse_confidence_score: confidence in abuse (0-100)
            - total_reports: number of abuse reports
            - last_reported: timestamp of last report
            - is_tor: whether it's a Tor exit node
            - is_proxy: whether it's a proxy
            - is_whitelisted: whether it's whitelisted

        # Temporal Information
        timestamps (dict | None):
            - first_seen: first observation timestamp
            - last_seen: last observation timestamp
            - last_analysis: last analysis timestamp
            - last_modified: last modification timestamp

        # Tags and Categories
        tags (list[str]): List of tags/labels
        categories (list[str]): Categorizations (phishing, malware, etc.)

        # File-specific data (for file_hash IOCs)
        file_info (dict | None):
            - file_type: type of file
            - file_size: size in bytes
            - magic: file magic description
            - names: known file names
            - ssdeep: ssdeep fuzzy hash
            - md5: MD5 hash
            - sha1: SHA1 hash
            - sha256: SHA256 hash

        # Domain-specific data
        domain_info (dict | None):
            - registrar: domain registrar
            - creation_date: domain creation date
            - expiration_date: domain expiration date
            - whois_date: whois lookup date
            - nameservers: list of nameservers

        # Additional data
        additional_info (dict): Any other source-specific information
    """

    def __init__(
        self,
        source: str,
        ioc_type: str,
        ioc: str,
        reputation_score: int | None = None,
        malicious: bool | None = None,
        confidence_score: int | None = None,
        detection_stats: dict | None = None,
        geo_info: dict | None = None,
        network_info: dict | None = None,
        abuse_info: dict | None = None,
        timestamps: dict | None = None,
        tags: list[str] | None = None,
        categories: list[str] | None = None,
        file_info: dict | None = None,
        domain_info: dict | None = None,
        additional_info: dict | None = None,
    ):
        self.schema_version = "1.0"
        self.normalized_time = datetime.now(timezone.utc).isoformat()
        self.source = source
        self.ioc_type = ioc_type
        self.ioc = ioc
        self.reputation_score = reputation_score
        self.malicious = malicious
        self.confidence_score = confidence_score
        self.detection_stats = detection_stats
        self.geo_info = geo_info
        self.network_info = network_info
        self.abuse_info = abuse_info
        self.timestamps = timestamps
        self.tags = tags or []
        self.categories = categories or []
        self.file_info = file_info
        self.domain_info = domain_info
        self.additional_info = additional_info or {}


def normalize_ip_virustotal_data(raw_data: dict) -> ThreatIntelligenceNormalizedSchema:
    """Normalize VirusTotal IP data into the common schema.

    Args:
        raw_data (dict): Raw JSON data from VirusTotal for an IP.

    Returns:
        ThreatIntelligenceNormalizedSchema: Normalized threat intelligence data.
    """
    data = raw_data.get("data", {})
    attributes = data.get("attributes", {})

    # Extract IP address
    ioc = data.get("id", "")

    # Calculate detection stats from last_analysis_results
    last_analysis_results = attributes.get("last_analysis_results", {})
    detection_stats = {
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "total": len(last_analysis_results),
    }

    for engine, result in last_analysis_results.items():
        category = result.get("category", "undetected")
        if category in detection_stats:
            detection_stats[category] += 1

    # Determine if malicious
    reputation = attributes.get("reputation")
    malicious = detection_stats["malicious"] > 0 or (
        reputation is not None and reputation < 0
    )

    # Extract network info
    network_info = {
        "asn": attributes.get("asn"),
        "organization": attributes.get("as_owner"),
    }

    # Extract geo info
    geo_info = {
        "country": attributes.get("country"),
        "continent": attributes.get("continent"),
    }

    # Extract timestamps
    timestamps = {
        "last_analysis": attributes.get("last_analysis_date"),
        "last_modified": attributes.get("last_modification_date"),
    }

    # Extract tags and categories
    tags = attributes.get("tags", [])
    categories = list(attributes.get("categories", {}).values())

    # Logging for debugging
    logger.debug("Normalized VirusTotal IP data for IOC %s: malicious=%s, reputation=%s", ioc, malicious, reputation)

    return ThreatIntelligenceNormalizedSchema(
        source="VirusTotal",
        ioc_type="ip",
        ioc=ioc,
        reputation_score=reputation,
        malicious=malicious,
        detection_stats=detection_stats,
        geo_info=geo_info,
        network_info=network_info,
        timestamps=timestamps,
        tags=tags,
        categories=categories,
    )


def normalize_file_hash_virustotal_data(
    raw_data: dict,
) -> ThreatIntelligenceNormalizedSchema:
    """Normalize VirusTotal file hash data into the common schema.

    Args:
        raw_data (dict): Raw JSON data from VirusTotal for a file hash.

    Returns:
        ThreatIntelligenceNormalizedSchema: Normalized threat intelligence data.
    """
    data = raw_data.get("data", {})
    attributes = data.get("attributes", {})

    # Extract file hash
    ioc = data.get("id", "")

    # Extract detection stats
    last_analysis_stats = attributes.get("last_analysis_stats", {})
    detection_stats = {
        "malicious": last_analysis_stats.get("malicious", 0),
        "suspicious": last_analysis_stats.get("suspicious", 0),
        "harmless": last_analysis_stats.get("harmless", 0),
        "undetected": last_analysis_stats.get("undetected", 0),
        "total": sum(last_analysis_stats.values()) if last_analysis_stats else 0,
    }

    # Determine if malicious
    malicious = detection_stats["malicious"] > 0
    reputation = attributes.get("reputation")

    # Calculate confidence score based on detection ratio
    confidence_score = None
    if detection_stats["total"] > 0:
        confidence_score = int(
            (detection_stats["malicious"] / detection_stats["total"]) * 100
        )

    # Extract file info
    known_distributors = attributes.get("known_distributors", {})
    file_info = {
        "file_type": attributes.get("type_description"),
        "file_size": attributes.get("size"),
        "magic": attributes.get("magic"),
        "names": known_distributors.get("filenames", []),
        "ssdeep": attributes.get("ssdeep"),
        "md5": attributes.get("md5"),
        "sha1": attributes.get("sha1"),
        "sha256": attributes.get("sha256"),
    }

    # Extract timestamps
    timestamps = {
        "first_seen": attributes.get("first_submission_date"),
        "last_seen": attributes.get("last_submission_date"),
        "last_analysis": attributes.get("last_analysis_date"),
        "last_modified": attributes.get("last_modification_date"),
    }

    # Extract tags and categories
    tags = attributes.get("tags", [])

    # Extract sandbox verdicts as categories
    sandbox_verdicts = attributes.get("sandbox_verdicts", {})
    categories = []
    for sandbox_name, verdict_info in sandbox_verdicts.items():
        if isinstance(verdict_info, dict):
            category = verdict_info.get("category")
            if category:
                categories.append(category)
            malware_classification = verdict_info.get("malware_classification", [])
            categories.extend(malware_classification)

    # Add distributors info to additional_info
    additional_info = {
        "times_submitted": attributes.get("times_submitted"),
        "unique_sources": attributes.get("unique_sources"),
        "known_distributors": known_distributors.get("distributors", []),
        "products": known_distributors.get("products", []),
    }

    # Logging for debugging
    logger.debug("Normalized VirusTotal file hash data for IOC %s: malicious=%s, reputation=%s", ioc, malicious, reputation)

    return ThreatIntelligenceNormalizedSchema(
        source="VirusTotal",
        ioc_type="file_hash",
        ioc=ioc,
        reputation_score=reputation,
        malicious=malicious,
        confidence_score=confidence_score,
        detection_stats=detection_stats,
        file_info=file_info,
        timestamps=timestamps,
        tags=tags,
        categories=categories,
        additional_info=additional_info,
    )


def normalize_domain_virustotal_data(
    raw_data: dict,
) -> ThreatIntelligenceNormalizedSchema:
    """Normalize VirusTotal domain data into the common schema.

    Args:
        raw_data (dict): Raw JSON data from VirusTotal for a domain.

    Returns:
        ThreatIntelligenceNormalizedSchema: Normalized threat intelligence data.
    """
    data = raw_data.get("data", {})
    attributes = data.get("attributes", {})

    # Extract domain
    ioc = data.get("id", "")

    # Calculate detection stats from last_analysis_results
    last_analysis_results = attributes.get("last_analysis_results", {})
    detection_stats = {
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "total": len(last_analysis_results),
    }

    for engine, result in last_analysis_results.items():
        category = result.get("category", "undetected")
        if category in detection_stats:
            detection_stats[category] += 1

    # Determine if malicious
    reputation = attributes.get("reputation")
    malicious = detection_stats["malicious"] > 0 or (
        reputation is not None and reputation < 0
    )

    # Extract total votes for confidence
    total_votes = attributes.get("total_votes", {})
    harmless_votes = total_votes.get("harmless", 0)
    malicious_votes = total_votes.get("malicious", 0)
    total_vote_count = harmless_votes + malicious_votes

    confidence_score = None
    if total_vote_count > 0:
        confidence_score = int((malicious_votes / total_vote_count) * 100)

    # Extract domain info
    whois = attributes.get("whois", "")
    registrar = None
    if "Registrar:" in whois:
        for line in whois.split("\n"):
            if line.startswith("Registrar:"):
                registrar = line.split(":", 1)[1].strip()
                break

    # Extract creation date from whois
    creation_date = None
    if "Creation Date:" in whois:
        for line in whois.split("\n"):
            if line.startswith("Creation Date:"):
                creation_date = line.split(":", 1)[1].strip()
                break

    domain_info = {
        "registrar": registrar,
        "creation_date": creation_date,
        "expiration_date": attributes.get("expiration_date"),
        "whois_date": attributes.get("whois_date"),
        "tld": attributes.get("tld"),
    }

    # Extract timestamps
    timestamps = {
        "last_analysis": attributes.get("last_analysis_date"),
        "last_modified": attributes.get("last_update_date"),
    }

    # Extract tags and categories
    tags = attributes.get("tags", [])
    categories = list(attributes.get("categories", {}).values())

    # Extract popularity ranks
    popularity_ranks = attributes.get("popularity_ranks", {})
    additional_info = {
        "popularity_ranks": popularity_ranks,
        "total_votes": total_votes,
    }

    # Logging for debugging
    logger.debug("Normalized VirusTotal domain data for IOC %s: malicious=%s, reputation=%s", ioc, malicious, reputation)

    return ThreatIntelligenceNormalizedSchema(
        source="VirusTotal",
        ioc_type="domain",
        ioc=ioc,
        reputation_score=reputation,
        malicious=malicious,
        confidence_score=confidence_score,
        detection_stats=detection_stats,
        domain_info=domain_info,
        timestamps=timestamps,
        tags=tags,
        categories=categories,
        additional_info=additional_info,
    )


def normalize_abuseipdb_data(raw_data: dict) -> ThreatIntelligenceNormalizedSchema:
    """Normalize AbuseIPDB data into the common schema.

    Args:
        raw_data (dict): Raw JSON data from AbuseIPDB for an IP.

    Returns:
        ThreatIntelligenceNormalizedSchema: Normalized threat intelligence data.
    """
    data = raw_data.get("data", {})

    # Extract IP address
    ioc = data.get("ipAddress", "")

    # Get abuse confidence score
    abuse_confidence = data.get("abuseConfidenceScore", 0)

    # Determine if malicious (typically >50% confidence)
    malicious = abuse_confidence > 50

    # Build abuse info
    abuse_info = {
        "abuse_confidence_score": abuse_confidence,
        "total_reports": data.get("totalReports", 0),
        "last_reported": data.get("lastReportedAt"),
        "is_tor": data.get("isTor", False),
        "is_whitelisted": data.get("isWhitelisted", False),
        "num_distinct_users": data.get("numDistinctUsers", 0),
    }

    # Build geo info
    geo_info = {
        "country": data.get("countryCode"),
    }

    # Build network info
    network_info = {
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "hostnames": data.get("hostnames", []),
        "usage_type": data.get("usageType"),
    }

    # Additional info
    additional_info = {
        "is_public": data.get("isPublic"),
        "ip_version": data.get("ipVersion"),
    }

    # Logging for debugging
    logger.debug("Normalized AbuseIPDB data for IOC %s: malicious=%s, abuse_confidence=%s", ioc, malicious, abuse_confidence)

    return ThreatIntelligenceNormalizedSchema(
        source="AbuseIPDB",
        ioc_type="ip",
        ioc=ioc,
        malicious=malicious,
        confidence_score=abuse_confidence,
        geo_info=geo_info,
        network_info=network_info,
        abuse_info=abuse_info,
        additional_info=additional_info,
    )


def normalize_ipinfo_data(raw_data: dict) -> ThreatIntelligenceNormalizedSchema:
    """Normalize ipinfo.io data into the common schema.

    Args:
        raw_data (dict): Raw JSON data from ipinfo.io for an IP.

    Returns:
        ThreatIntelligenceNormalizedSchema: Normalized threat intelligence data.
    """
    # Extract IP address
    ioc = raw_data.get("ip", "")

    # Build geo info
    geo_info = {
        "country": raw_data.get("country"),
        "city": raw_data.get("city"),
        "region": raw_data.get("region"),
        "coordinates": raw_data.get("loc"),
        "timezone": raw_data.get("timezone"),
        "postal": raw_data.get("postal"),
    }

    # Build network info
    # Parse ASN from org field (format: "AS15169 Google LLC")
    org = raw_data.get("org", "")
    asn = None
    organization = org
    if org.startswith("AS"):
        parts = org.split(" ", 1)
        if len(parts) == 2:
            asn = parts[0]
            organization = parts[1]

    network_info = {
        "asn": asn,
        "organization": organization,
        "hostnames": [raw_data.get("hostname")] if raw_data.get("hostname") else [],
    }

    # Additional info
    additional_info = {
        "anycast": raw_data.get("anycast"),
    }

    # Logging for debugging
    logger.debug("Normalized ipinfo.io data for IOC %s", ioc)

    return ThreatIntelligenceNormalizedSchema(
        source="ipinfo.io",
        ioc_type="ip",
        ioc=ioc,
        geo_info=geo_info,
        network_info=network_info,
        additional_info=additional_info,
    )
