import json
import os
import requests

# Internal imports
from common.helper_functions import (
    retrieve_secrets,
    unix_timestamp_to_iso,
    add_argparser_arguments,
)

# Read .env and import the API key
vt_api_key = retrieve_secrets("vt_api_key")


def vt_domain_lookup(
    input_domain: str,
    json_dir: str = "ip_osint_json",
    json_file: str = "vt_domain_lookup.json",
) -> bool:
    """Function to lookup a domain on VirusTotal and writes the response to a file. If the file write fails, the raw response is printed instead.

    If the API call is successful, the JSON response is written to a file called "vt_domain_lookup.json" and the function returns True.

    If the API call is unsuccessful or the file write fails, the function returns False.

    Args:
        input_domain: The domain to look up.
        json_dir: The directory to save the JSON response file. Default is "domain_osint_json".
        json_file: The filename of the JSON response file. Default is "vt_domain_lookup.json".

    Returns:
        bool: True if the API call was successful, False otherwise.
    """
    # Set up parameters for the API call
    url = f"https://www.virustotal.com/api/v3/domains/{input_domain}"

    headers = {"x-apikey": vt_api_key}

    # Make the API call
    response = requests.request("GET", url, headers=headers)

    # If the response is successful, return the JSON data
    if response.status_code == 200:
        try:
            with open(os.path.join(json_dir, json_file), "w") as f:
                json.dump(response.json(), f, indent=2)
                return True
        except IOError or OSError:
            print("Error writing to file, returning raw response instead.")
            print(response.text())
            return False
        except:
            print("Unknown error occurred.")
            return False
    # Else, return False
    else:
        return False


def vt_check_domain(
    response_json_dir: str = "ip_osint_json",
    response_json_file: str = "vt_domain_lookup.json",
) -> dict:
    """Function to check the response from a VirusTotal domain lookup and return the analysis results.

    Args:
        response_json_dir: The directory where the JSON response file is saved. Default is "ip_osint_json".
        response_json_file: The filename of the JSON response file. Default is "vt_domain_lookup.json".

    Returns:
        dict: A dictionary containing the vendors that detected the IP address as malicious and number of vendors from the JSON response.
    """
    # Form the file path to read
    response_json_dir_file = os.path.join(response_json_dir, response_json_file)
    with open(response_json_dir_file, "r") as f:
        response = json.load(f)

    # Initialize list of IP addresses
    ipv4_addresses = []
    ipv6_addresses = []

    # Initialize list of alternate domains
    alternate_domains = []

    # Initialize list of vendors that detected the IP address as malicious
    vendors_detected_malicious = []

    # Get the last analysis date
    last_analysis_date_iso = unix_timestamp_to_iso(
        response["data"]["attributes"]["last_analysis_date"]
    )

    # Get IP address from A and AAAA records
    for record in response["data"]["attributes"]["last_dns_records"]:
        if record["type"] == "A":
            ipv4_addresses.append(record["value"])
        elif record["type"] == "AAAA":
            ipv6_addresses.append(record["value"])

    # Get alternate domains from CNAME records
    for record in response["data"]["attributes"]["last_dns_records"]:
        if record["type"] == "CNAME":
            alternate_domains.append(record["value"])

    # Get total number of vendors that detected the domain as malicious
    total_vendors = (
        response["data"]["attributes"]["last_analysis_stats"]["malicious"]
        + response["data"]["attributes"]["last_analysis_stats"]["suspicious"]
        + response["data"]["attributes"]["last_analysis_stats"]["undetected"]
        + response["data"]["attributes"]["last_analysis_stats"]["harmless"]
        + response["data"]["attributes"]["last_analysis_stats"]["timeout"]
    )

    # Update list of vendors that detected the domain as malicious
    for vendor in response["data"]["attributes"]["last_analysis_results"]:
        if (
            response["data"]["attributes"]["last_analysis_results"][vendor]["category"]
            == "malicious"
            or response["data"]["attributes"]["last_analysis_results"][vendor][
                "category"
            ]
            == "malware"
        ):
            vendors_detected_malicious.append(vendor)

    # Set the count of vendors that detected the domain as malicious
    if vendors_detected_malicious:
        num_vendors_detected_malicious = (
            f"{len(vendors_detected_malicious)}/{total_vendors}"
        )
    else:
        num_vendors_detected_malicious = 0

    # Return details as a dictionary
    return {
        "domain": response["data"]["id"],
        "ipv4_addresses": ipv4_addresses,
        "ipv6_addresses": ipv6_addresses,
        "alternate_domains": alternate_domains,
        "last_analysis_date": last_analysis_date_iso,
        "num_vendors_detected_malicious": num_vendors_detected_malicious,
        "vendors_detected_malicious": vendors_detected_malicious,
    }


def nice_print_vt_domain_osint(domain_osint: dict) -> None:
    """Function to print the VirusTotal domain lookup results in a user-friendly format. This is necessary if the user runs this script directly.

    Args:
        domain_osint: The dictionary containing the domain OSINT details from vt_check_domain().

    Returns:
        None
    """
    # Print the domain OSINT details
    print(f"Domain: {domain_osint['domain']}")
    print(f"Last Analysis Date: {domain_osint['last_analysis_date']}")

    # Print the IPv4 addresses
    if domain_osint["ipv4_addresses"]:
        print(f"IPv4 Addresses: {', '.join(domain_osint['ipv4_addresses'])}")
    else:
        print("No IPv4 addresses found.")

    # Print the IPv6 addresses
    if domain_osint["ipv6_addresses"]:
        print(f"IPv6 Addresses: {', '.join(domain_osint['ipv6_addresses'])}")
    else:
        print("No IPv6 addresses found.")

    # Print the alternate domains
    if domain_osint["alternate_domains"]:
        print(f"Alternate Domains: {', '.join(domain_osint['alternate_domains'])}")
    else:
        print("No alternate domains found.")

    # Check for vendors that detected the domain as malicious
    if domain_osint["vendors_detected_malicious"]:
        print(
            f"The following VT vendors detected this domain as malicious: {', '.join(domain_osint['vendors_detected_malicious'])}"
        )
    else:
        print("This domain is clean in VirusTotal.")

    # Print the number of vendors that detected the domain as malicious
    print(
        f"Number of vendors that detected this domain as malicious: {domain_osint['num_vendors_detected_malicious']}"
    )


def main():
    # Set up argparser with arguments
    args = add_argparser_arguments(domain=True, response_file=True, response_dir=True)

    # Retrieve values from the command line arguments
    domain = args.domain
    response_file = args.response_file
    response_dir = args.response_dir

    # Decision tree for the arguments
    if domain and response_file:
        raise ValueError("Please provide only one of --ip or --response_file.")
    # If the domain is provided, perform the VirusTotal domain lookup
    elif domain:
        lookup_domain_success = False
        lookup_domain_success = vt_domain_lookup(input_domain=domain)
        if lookup_domain_success:
            vt_data = vt_check_domain(response_json_file="vt_domain_lookup.json")
            nice_print_vt_domain_osint(vt_data)
        else:
            print("Error with the VirusTotal API call.")
    # If both the response file and directory are provided, use them
    elif response_file and response_dir:
        vt_data = vt_check_domain(
            response_json_file=response_file, response_json_dir=response_dir
        )
        nice_print_vt_domain_osint(vt_data)
    # If only the response file is provided, use the default directory
    elif response_file and not response_dir:
        print(
            "No response directory provided. Using default directory 'domain_osint_json'."
        )
        vt_data = vt_check_domain(response_json_file=response_file)
        nice_print_vt_domain_osint(vt_data)
    # If only the response directory is provided, print an error
    elif response_dir and not response_file:
        raise ValueError(
            "Please provide the response file (--response_file <file>) with the response directory."
        )
    # If no or invalid arguments are provided, print an error
    else:
        raise ValueError("Please provide one of --domain or --response_file.")


if __name__ == "__main__":
    main()
