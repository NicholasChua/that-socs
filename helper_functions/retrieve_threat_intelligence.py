"""Thin wrappers for several threat intelligence HTTP APIs.

This module provides small clients for VirusTotal, AbuseIPDB and ipinfo.io that reuse :class:`helper_functions.http_handler.BaseClient` for session and retry management. Environment variables are used to provide API keys when available.

Supported environment variables:
- `VIRUSTOTAL_API_KEY`
- `ABUSEIPDB_API_KEY`
- `IPINFO_API_KEY`

The clients expose simple `fetch_*` methods returning parsed JSON responses from the respective services.
"""

import os
import requests
from dotenv import load_dotenv
from helper_functions.http_handler import BaseClient


class VirusTotalClient(BaseClient):
    """Client for querying VirusTotal for IPs, files and domains.

    Args:
        session (requests.Session | None): Optional session passed to class:`BaseClient`.

    Attributes:
        api_key (str | None): Value of the `VIRUSTOTAL_API_KEY` environment variable.
        headers (dict): Default headers to send with requests.
    """

    def __init__(self, session: requests.Session | None = None):
        super().__init__(session=session)
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.headers = {"x-apikey": self.api_key}

    def fetch_ip(self, ip: str) -> dict:
        """Fetch IP information from VirusTotal.

        Args:
            ip (str): IP address to query.

        Returns:
            dict: Parsed JSON response from the VirusTotal API.
        """
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        response = self.request("GET", url, headers=self.headers, timeout=10)
        return response.json()

    def fetch_file(self, file_hash: str) -> dict:
        """Fetch file hash information from VirusTotal.

        Args:
            file_hash (str): File hash to query.

        Returns:
            dict: Parsed JSON response.
        """
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        response = self.request("GET", url, headers=self.headers, timeout=10)
        return response.json()

    def fetch_domain(self, domain: str) -> dict:
        """Fetch domain information from VirusTotal.

        Args:
            domain (str): Domain name to query.

        Returns:
            dict: Parsed JSON response.
        """
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        response = self.request("GET", url, headers=self.headers, timeout=10)
        return response.json()


class AbuseIPDBClient(BaseClient):
    """Client for querying AbuseIPDB for IP reputation data.

    Args:
        session (requests.Session | None): Optional session passed to :class:`BaseClient`.
    """

    def __init__(self, session: requests.Session | None = None):
        super().__init__(session=session)
        self.api_key = os.getenv("ABUSEIPDB_API_KEY")
        self.headers = {"Key": self.api_key, "Accept": "application/json"}

    def fetch_ip(self, ip: str, max_age_days: int = 90) -> dict:
        """Fetch an IP report from AbuseIPDB.

        Args:
            ip (str): IP address to query.
            max_age_days (int): Maximum age in days for returned reports.

        Returns:
            dict: Parsed JSON response.
        """
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": ip, "maxAgeInDays": max_age_days}
        response = self.request(
            "GET", url, headers=self.headers, params=params, timeout=10
        )
        return response.json()


class IPInfoClient(BaseClient):
    """Client for querying ipinfo.io for IP metadata.

    Args:
        session (requests.Session | None): Optional session passed to :class:`BaseClient`.

    Attributes:
        api_key (str | None): Value of the `IPINFO_API_KEY` environment variable; if not provided ipinfo allows unauthenticated requests with stricter rate limits.
    """

    def __init__(self, session: requests.Session | None = None):
        super().__init__(session=session)
        self.api_key = os.getenv("IPINFO_API_KEY")

    def fetch_ip(self, ip: str) -> dict:
        """Fetch IP metadata from ipinfo.io.

        Args:
            ip (str): IP address to query.

        Returns:
            dict: Parsed JSON response.
        """
        url = f"https://ipinfo.io/{ip}/json"
        params = (
            {"token": self.api_key} if self.api_key else None
        )  # ipinfo allows unauthenticated requests with limits
        response = self.request("GET", url, params=params, timeout=10)
        return response.json()


# Import environment variables from .env file
load_dotenv()
