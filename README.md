# That SOCs

Spiritual successor to my old project [siem_osint_automation](https://github.com/NicholasChua/siem_osint_automation) enhanced with more modularity, logging, and better coding practices.

## Planned Workflow

`That SOCs` currently covers the `Logging`, `IOC Extraction`, `Threat Intelligence Retrieval`, `Normalization`, `Enrichment` stages of the below planned workflow:

- **Alert Retrieval**: Fetches open (unassigned) security alerts from specified sources.
- **IOC Extraction**: Extracts Indicators of Compromise (IOCs) from the alerts.
- **Threat Intelligence Retrieval**: Queries threat intelligence sources for information related to the extracted IOCs.
- **Normalization**: Standardizes the retrieved threat intelligence data into a consistent format.
- **Enrichment**: Augments the original alerts with the normalized threat intelligence data.
- **Alert Update**: Updates the status of the alerts based on the investigation results.
- **Logging**: Logs all activities for auditing and debugging purposes.

## Requirements

This project was tested on Python 3.14.2.

- Python 3 (latest version recommended)
- VirusTotal API key (free tier is sufficient)
- ipinfo.io API key (free tier is sufficient)
- AbuseIPDB API key (free tier is sufficient)
- .env file containing API keys

## How to Get API Keys

### VirusTotal

1. Register for a free VirusTotal account: [https://www.virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us).

![VirusTotal Sign Up Page](readme_media/vt_signup.png)

2. Once logged in, click on the top-right corner where your profile icon is and select "API Key". This will direct you to the [API Key page](https://www.virustotal.com/gui/my-apikey).

![VirusTotal Select API Key](readme_media/vt_select_api_key.png)

3. Under API Key, click on "Copy to clipboard" to copy your API key

![VirusTotal API Key](readme_media/vt_api_key_copy.png)

### ipinfo.io

1. Register for a free IPinfo account: [https://ipinfo.io/signup](https://ipinfo.io/signup).

![ipinfo Sign Up Page](readme_media/ii_signup.png)

2. Once logged in and on the [home page](https://ipinfo.io/account/home), scroll down to `Step 3: Get your token`, and click on `Copy` to copy your API key.

![ipinfo API Key](readme_media/ii_api_key.png)

### AbuseIPDB

1. Register for a free AbuseIPDB account: [https://www.abuseipdb.com/register?plan=free](https://www.abuseipdb.com/register?plan=free).

![AbuseIPDB Sign Up](readme_media/ai_signup.png)

2. After registering, log in to your account and navigate to the [API Key page](https://www.abuseipdb.com/account/api). You can create a new API key by clicking on the `Create Key` button under the `Keys` section.

![AbuseIPDB Create API Key](readme_media/ai_create_api_key.png)

3. Give the key a name, then click on `Create` and the `Copy to Clipboard` button to copy your API key.

![AbuseIPDB API Key](readme_media/ai_api_key.png)

### secrets.json

**`Warning`**: Do not share, upload, commit, or otherwise expose your API keys to the public. This can lead to unauthorized access and usage of your API keys. The `.env` file is used to store your API keys in a secure manner, and has been added to the `.gitignore` file to prevent accidental exposure.

1. Copy the `.env.example` file and rename it to `.env`. It should be in the root directory of the project with the following format:

```text
VIRUSTOTAL_API_KEY=YOUR VIRUSTOTAL API KEY
IPINFO_API_KEY=YOUR IPINFO API KEY
ABUSEIPDB_API_KEY=YOUR ABUSEIPDB API KEY
```

2. Replace `YOUR VIRUSTOTAL API KEY`, `YOUR IPINFO API KEY`, `YOUR ABUSEIPDB API KEY` with the respective API keys you obtained in the previous steps.

3. Ensure that the `.env` file is in the root directory of the project.

## Usage

1. Install the required Python packages using pip:

```bash
pip install -r requirements.txt
```

2. TODO: Create a main script to run the workflow
