# SIEM Automation Project

This project is a collection of Python scripts that can be used to automate various OSINT tasks based on data from SIEMs. This helps improve response time and efficiency in incident response and threat hunting. These scripts are designed to work based on data outputted by SIEMs, such as IP addresses, domains, and hashes, rather than directly interfacing with the SIEM itself.

## Requirements

This project was tested on Python 3.12.3.

- Python 3.12+
- VirusTotal API key (free tier is sufficient)
- ipinfo.io API key (free tier is sufficient)
- secrets.json file containing API keys

## File Structure

I assume the following file structure:

```plaintext
.
├───.venv
├───.gitignore
├───README.md
├───requirements.txt
├───LICENSE
├───ip_osint_json
│   ├───vt_ip_lookup.json (Output from vt_ip_osint.py)
|   └───ii_ip_lookup.json (Output from ipinfo_ip_osint.py)
├───vt_ip_osint.py
├───ipinfo_ip_osint.py
└───secrets.json
```

## Installation

1. Clone the repository:

```bash
git clone https://github.com/NicholasChua/siem_osint_automation.git
```

2. Install the required Python packages:

```bash
pip install -r requirements.txt
```

3. Create a `secrets.json` file in the root directory of the project with the following format:

```json
{
    "vt_api_key": "YOUR VIRUSTOTAL API KEY",
    "ip_info_api_key": "YOUR IPINFO API KEY"
}
```

## Usage

##### `vt_ip_osint.py`

This script takes in IP addresses as input and queries VirusTotal for information on the IP addresses. The script then outputs the response to a .json file. The file is then further processed to extract relevant information (e.g. which vendors consider it malicious) and return it to the user.

```bash
python vt_ip_osint.py --ip 8.8.8.8
```

The script will output `vt_ip_lookup.json` file in the `ip_osint_json` directory if the user wishes to look at the full VirusTotal response. Note that the output file is overwritten each time the script is run.

##### `ipinfo_ip_osint.py`

This script takes in IP addresses as input and queries ipinfo.io for information on the IP addresses. The script then outputs the response to a .json file. The file is then further processed to extract relevant information (e.g. city, region, org, country) and return it to the user.

```bash
python ipinfo_ip_osint.py --ip 8.8.8.8
```

The script will output `ii_ip_lookup.json` file in the `ip_osint_json` directory if the user wishes to look at the full ipinfo.io response. Note that the output file is overwritten each time the script is run.

## To Do

- [x] Implement VirusTotal IP Lookup script via API
- [x] Implement ipinfo.io IP Lookup script via API
- [ ] Implement Cisco Talos IP Reputation Lookup script via web scraping?
- [ ] Automated comment generation for each script (i.e. timestamp, IP address, etc.)
- [ ] Main file to run all scripts together
- [ ] SIEM integration (not public)
- [ ] Excel user attributes query (not public)
