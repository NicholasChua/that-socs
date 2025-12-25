import helper_functions.retrieve_threat_intelligence as rti
import helper_functions.normalize_threat_intelligence as nti
from helper_functions.enrichment import combined_enrichment
import json


def main():
    """Example main function to demonstrate data retrieval, normalization, and enrichment. If you want to verify the actual functions themselves, run `pytest tests/` from the command line instead of this script.    
    """
    # Test data retrieval

    # Example IOCs to query
    ip_address = "118.25.6.39"
    file_hash = "44d88612fea8a8f36de82e1278abb02f"
    domain_name = "polyfill.io"

    # Initialize clients
    vt_client = rti.VirusTotalClient()
    abuse_client = rti.AbuseIPDBClient()
    ipinfo_client = rti.IPInfoClient()

    # Fetch data from VirusTotal
    vt_ip_data = vt_client.fetch_ip(ip_address)
    vt_file_data = vt_client.fetch_file(file_hash)
    vt_domain_data = vt_client.fetch_domain(domain_name)

    # Fetch data from AbuseIPDB
    abuse_data = abuse_client.fetch_ip(ip_address)

    # Fetch data from IPInfo
    ipinfo_data = ipinfo_client.fetch_ip(ip_address)

    # Save data before normalization
    with open("ip_virustotal_result.json", "w") as f:
        json.dump(vt_ip_data, f, indent=4)
    with open("file_hash_virustotal_result.json", "w") as f:
        json.dump(vt_file_data, f, indent=4)
    with open("domain_virustotal_result.json", "w") as f:
        json.dump(vt_domain_data, f, indent=4)
    with open("abuseipdb_result.json", "w") as f:
        json.dump(abuse_data, f, indent=4)
    with open("ipinfo_result.json", "w") as f:
        json.dump(ipinfo_data, f, indent=4)

    # Test data normalization

    # Load previously saved data
    with open("abuseipdb_result.json", "r") as f:
        abuse_data = json.load(f)
    with open("ipinfo_result.json", "r") as f:
        ipinfo_data = json.load(f)
    with open("ip_virustotal_result.json", "r") as f:
        vt_ip_data = json.load(f)
    with open("file_hash_virustotal_result.json", "r") as f:
        vt_file_data = json.load(f)
    with open("domain_virustotal_result.json", "r") as f:
        vt_domain_data = json.load(f)

    # Normalize data
    abuseipdb_normalized = nti.normalize_abuseipdb_data(abuse_data)
    ipinfo_normalized = nti.normalize_ipinfo_data(ipinfo_data)
    virustotal_ip_normalized = nti.normalize_ip_virustotal_data(vt_ip_data)
    virustotal_file_hash_normalized = nti.normalize_file_hash_virustotal_data(vt_file_data)
    virustotal_domain_normalized = nti.normalize_domain_virustotal_data(vt_domain_data)

    # Save normalized outputs as `normalized_*.json` files
    with open("normalized_abuseipdb.json", "w") as f:
        json.dump(abuseipdb_normalized.__dict__, f, indent=4)
    with open("normalized_ipinfo.json", "w") as f:
        json.dump(ipinfo_normalized.__dict__, f, indent=4)
    with open("normalized_ip_virustotal.json", "w") as f:
        json.dump(virustotal_ip_normalized.__dict__, f, indent=4)
    with open("normalized_file_hash_virustotal.json", "w") as f:
        json.dump(virustotal_file_hash_normalized.__dict__, f, indent=4)
    with open("normalized_domain_virustotal.json", "w") as f:
        json.dump(virustotal_domain_normalized.__dict__, f, indent=4)

    # Test enrichment

    # Load previously saved data
    with open("normalized_abuseipdb.json", "r") as f:
        abuse_data = json.load(f)
    with open("normalized_ipinfo.json", "r") as f:
        ipinfo_data = json.load(f)
    with open("normalized_ip_virustotal.json", "r") as f:
        vt_ip_data = json.load(f)
    with open("normalized_file_hash_virustotal.json", "r") as f:
        vt_file_data = json.load(f)
    with open("normalized_domain_virustotal.json", "r") as f:
        vt_domain_data = json.load(f)

    # Run combined comments
    enriched_comment = combined_enrichment(
        abuseipdb_data=abuse_data,
        ipinfo_data=ipinfo_data,
        ip_virustotal_data=vt_ip_data,
        domain_virustotal_data=vt_domain_data,
        file_hash_virustotal_data=vt_file_data,
    )

    print(enriched_comment)


if __name__ == "__main__":
    main()
