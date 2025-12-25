"""Thin wrappers for generating comments from normalized threat intelligence data.

This module supports normalized VirusTotal, AbuseIPDB and ipinfo.io threat intelligence data produced by the `normalize_threat_intelligence` module. Refer to the schema defined under :class:`ThreatIntelligenceNormalizedSchema` in that module for details on the expected input data structure.
"""

def enrich_abuseipdb(data: dict) -> str:
    """Enrich AbuseIPDB normalized data.
    
    Args:
        data: Normalized AbuseIPDB data dictionary
        
    Returns:
        str: A human-readable comment string
    """
    normalized_time = data.get("normalized_time", "Unknown")
    ioc = data.get("ioc", "Unknown")
    malicious = data.get("malicious", "Unknown")
    confidence = data.get("confidence_score", "Unknown")
    abuse_info = data.get("abuse_info", {})
    
    comment = f"Analyzed at: {normalized_time}\n"
    comment += f"AbuseIPDB Link: https://www.abuseipdb.com/check/{ioc}\n"
    comment += f"Defanged IP: {ioc.replace('.', '[.]')}\n"
    comment += f"Status: {'Malicious' if malicious else 'Clean'}\n"
    comment += f"Abuse Confidence Score: {confidence}%\n"
    
    if abuse_info:
        total_reports = abuse_info.get("total_reports", 0)
        distinct_users = abuse_info.get("num_distinct_users", 0)
        last_reported = abuse_info.get("last_reported", "N/A")
        
        comment += f"Total Reports: {total_reports} from {distinct_users} distinct users\n"
        comment += f"Last Reported: {last_reported}\n"
        
        if abuse_info.get("is_tor"):
            comment += "⚠️ This IP is associated with TOR\n"
        if abuse_info.get("is_whitelisted"):
            comment += "✓ This IP is whitelisted\n"
    
    geo_info = data.get("geo_info", {})
    if geo_info:
        comment += f"Country: {geo_info.get('country', 'Unknown')}\n"
    
    network_info = data.get("network_info", {})
    if network_info:
        comment += f"ISP: {network_info.get('isp', 'Unknown')}\n"
        usage_type = network_info.get("usage_type")
        if usage_type:
            comment += f"Usage Type: {usage_type}\n"
    
    return comment


def enrich_ipinfo(data: dict) -> str:
    """Enrich ipinfo.io normalized data.
    
    Args:
        data: Normalized ipinfo.io data dictionary
        
    Returns:
        str: A human-readable comment string
    """
    time_generated = data.get("normalized_time", "Unknown")
    ioc = data.get("ioc", "Unknown")
    
    comment = f"Analyzed at: {time_generated}\n"
    comment += f"ipinfo.io Link: https://ipinfo.io/{ioc}\n"
    comment += f"Defanged IP: {ioc.replace('.', '[.]')}\n"
    
    geo_info = data.get("geo_info", {})
    if geo_info:
        city = geo_info.get("city", "Unknown")
        region = geo_info.get("region", "Unknown")
        country = geo_info.get("country", "Unknown")
        coordinates = geo_info.get("coordinates", "Unknown")
        timezone = geo_info.get("timezone", "Unknown")
        postal = geo_info.get("postal", "Unknown")
        
        comment += f"Location: {city}, {region}, {country}\n"
        comment += f"Coordinates: {coordinates}\n"
        comment += f"Timezone: {timezone}\n"
        comment += f"Postal Code: {postal}\n"
    
    network_info = data.get("network_info", {})
    if network_info:
        asn = network_info.get("asn", "Unknown")
        org = network_info.get("organization", "Unknown")
        comment += f"ASN: {asn}\n"
        comment += f"Organization: {org}\n"
        
        hostnames = network_info.get("hostnames", [])
        if hostnames:
            comment += f"Hostnames: {', '.join(hostnames)}\n"
    
    return comment


def enrich_ip_virustotal(data: dict) -> str:
    """Enrich VirusTotal IP normalized data.
    
    Args:
        data: Normalized VirusTotal IP data dictionary
        
    Returns:
        str: A human-readable comment string
    """
    time_generated = data.get("normalized_time", "Unknown")
    ioc = data.get("ioc", "Unknown")
    malicious = data.get("malicious", False)
    reputation = data.get("reputation_score", 0)
    
    comment = f"Analyzed at: {time_generated}\n"
    comment += f"VirusTotal Link: https://www.virustotal.com/gui/ip-address/{ioc}\n"
    comment += f"Defanged IP: {ioc.replace('.', '[.]')}\n"
    comment += f"Status: {'Malicious' if malicious else 'Clean'}\n"
    comment += f"Reputation Score: {reputation}\n"
    
    detection_stats = data.get("detection_stats", {})
    if detection_stats:
        malicious_count = detection_stats.get("malicious", 0)
        suspicious_count = detection_stats.get("suspicious", 0)
        harmless_count = detection_stats.get("harmless", 0)
        undetected_count = detection_stats.get("undetected", 0)
        total = detection_stats.get("total", 0)
        
        comment += f"Detection: {malicious_count} malicious, {suspicious_count} suspicious, "
        comment += f"{harmless_count} harmless, {undetected_count} undetected ({total} total engines)\n"
    
    geo_info = data.get("geo_info", {})
    if geo_info:
        country = geo_info.get("country", "Unknown")
        continent = geo_info.get("continent", "Unknown")
        comment += f"Location: {country}, {continent}\n"
    
    network_info = data.get("network_info", {})
    if network_info:
        asn = network_info.get("asn", "Unknown")
        org = network_info.get("organization", "Unknown")
        comment += f"ASN: {asn}\n"
        comment += f"Organization: {org}\n"
    
    return comment


def enrich_domain_virustotal(data: dict) -> str:
    """Enrich VirusTotal domain normalized data.
    
    Args:
        data: Normalized VirusTotal domain data dictionary
        
    Returns:
        str: A human-readable comment string
    """
    time_generated = data.get("normalized_time", "Unknown")
    ioc = data.get("ioc", "Unknown")
    malicious = data.get("malicious", False)
    reputation = data.get("reputation_score", 0)
    confidence = data.get("confidence_score", 0)
    
    comment = f"Analyzed at: {time_generated}\n"
    comment += f"VirusTotal Link: https://www.virustotal.com/gui/domain/{ioc}\n"
    comment += f"Defanged Domain: {ioc.replace('.', '[.]')}\n"
    comment += f"Status: {'⚠️ MALICIOUS' if malicious else '✓ Clean'}\n"
    comment += f"Reputation Score: {reputation}\n"
    comment += f"Confidence Score: {confidence}%\n"
    
    detection_stats = data.get("detection_stats", {})
    if detection_stats:
        malicious_count = detection_stats.get("malicious", 0)
        suspicious_count = detection_stats.get("suspicious", 0)
        harmless_count = detection_stats.get("harmless", 0)
        undetected_count = detection_stats.get("undetected", 0)
        total = detection_stats.get("total", 0)
        
        comment += f"Detection: {malicious_count} malicious, {suspicious_count} suspicious, "
        comment += f"{harmless_count} harmless, {undetected_count} undetected ({total} total engines)\n"
    
    domain_info = data.get("domain_info", {})
    if domain_info:
        registrar = domain_info.get("registrar", "Unknown")
        creation_date = domain_info.get("creation_date", "Unknown")
        tld = domain_info.get("tld", "Unknown")
        
        comment += f"Registrar: {registrar}\n"
        comment += f"Creation Date: {creation_date}\n"
        comment += f"TLD: .{tld}\n"
    
    categories = data.get("categories", [])
    if categories:
        comment += f"Categories: {', '.join(categories[:5])}"
        if len(categories) > 5:
            comment += f" (+{len(categories) - 5} more)"
        comment += "\n"
    
    return comment


def enrich_file_hash_virustotal(data: dict) -> str:
    """Enrich VirusTotal file hash normalized data.
    
    Args:
        data: Normalized VirusTotal file hash data dictionary
        
    Returns:
        str: A human-readable comment string
    """
    time_generated = data.get("normalized_time", "Unknown")
    ioc = data.get("ioc", "Unknown")
    malicious = data.get("malicious", False)
    reputation = data.get("reputation_score", 0)
    confidence = data.get("confidence_score", 0)
    
    comment = f"Analyzed at: {time_generated}\n"
    comment += f"VirusTotal Link: https://www.virustotal.com/gui/file/{ioc}\n"
    comment += f"Status: {'🚨 MALICIOUS' if malicious else '✓ Clean'}\n"
    comment += f"Reputation Score: {reputation}\n"
    comment += f"Confidence Score: {confidence}%\n"
    
    detection_stats = data.get("detection_stats", {})
    if detection_stats:
        malicious_count = detection_stats.get("malicious", 0)
        suspicious_count = detection_stats.get("suspicious", 0)
        harmless_count = detection_stats.get("harmless", 0)
        undetected_count = detection_stats.get("undetected", 0)
        total = detection_stats.get("total", 0)
        
        comment += f"Detection: {malicious_count}/{total} engines flagged as malicious\n"
        comment += f"Details: {malicious_count} malicious, {suspicious_count} suspicious, "
        comment += f"{harmless_count} harmless, {undetected_count} undetected\n"
    
    file_info = data.get("file_info", {})
    if file_info:
        file_type = file_info.get("file_type", "Unknown")
        file_size = file_info.get("file_size", 0)
        names = file_info.get("names", [])
        md5 = file_info.get("md5", "Unknown")
        sha1 = file_info.get("sha1", "Unknown")
        sha256 = file_info.get("sha256", "Unknown")
        
        comment += f"File Type: {file_type}\n"
        comment += f"File Size: {file_size:,} bytes\n"
        comment += f"MD5: {md5}\n"
        comment += f"SHA1: {sha1}\n"
        comment += f"SHA256: {sha256}\n"
        
        if names:
            comment += f"Known Names: {', '.join(names[:3])}"
            if len(names) > 3:
                comment += f" (+{len(names) - 3} more)"
            comment += "\n"
    
    tags = data.get("tags", [])
    if tags:
        comment += f"Tags: {', '.join(tags[:8])}"
        if len(tags) > 8:
            comment += f" (+{len(tags) - 8} more)"
        comment += "\n"
    
    return comment


def combined_enrichment(
    abuseipdb_data: dict | None = None,
    ipinfo_data: dict | None = None,
    ip_virustotal_data: dict | None = None,
    domain_virustotal_data: dict | None = None,
    file_hash_virustotal_data: dict | None = None
) -> str:
    """Combine comments from multiple threat intelligence sources.
    
    Args:
        abuseipdb_data: Normalized AbuseIPDB data dictionary
        ipinfo_data: Normalized ipinfo.io data dictionary
        ip_virustotal_data: Normalized VirusTotal IP data dictionary
        domain_virustotal_data: Normalized VirusTotal domain data dictionary
        file_hash_virustotal_data: Normalized VirusTotal file hash data dictionary
        
    Returns:
        str: A combined human-readable comment string from all provided sources
    """
    comments = []
    
    if abuseipdb_data:
        comments.append("=" * 60)
        comments.append("ABUSEIPDB ANALYSIS")
        comments.append("=" * 60)
        comments.append(enrich_abuseipdb(abuseipdb_data))
    
    if ipinfo_data:
        comments.append("=" * 60)
        comments.append("IPINFO.IO ANALYSIS")
        comments.append("=" * 60)
        comments.append(enrich_ipinfo(ipinfo_data))
    
    if ip_virustotal_data:
        comments.append("=" * 60)
        comments.append("VIRUSTOTAL IP ANALYSIS")
        comments.append("=" * 60)
        comments.append(enrich_ip_virustotal(ip_virustotal_data))
    
    if domain_virustotal_data:
        comments.append("=" * 60)
        comments.append("VIRUSTOTAL DOMAIN ANALYSIS")
        comments.append("=" * 60)
        comments.append(enrich_domain_virustotal(domain_virustotal_data))
    
    if file_hash_virustotal_data:
        comments.append("=" * 60)
        comments.append("VIRUSTOTAL FILE HASH ANALYSIS")
        comments.append("=" * 60)
        comments.append(enrich_file_hash_virustotal(file_hash_virustotal_data))
    
    if not comments:
        return "No threat intelligence data provided."
    
    # Add summary header
    header = ["=" * 60, "That SOCs Enrichment Summary", "=" * 60, ""]
    
    return "\n".join(header + comments)
