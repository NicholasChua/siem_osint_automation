#!/usr/bin/env python3

import json
import os
import requests

# Internal imports
from common.helper_functions import (
    hash_file,
    retrieve_secrets,
    unix_timestamp_to_iso,
    ip_input_validation,
    hash_input_validation,
    add_argparser_arguments,
)

# Read .env and import the API key
vt_api_key = retrieve_secrets("vt_api_key")

# IP lookup functions

def vt_ip_lookup(
    input_ip: str, json_dir: str = "osint_json", json_file: str = "vt_ip_lookup.json"
) -> bool:
    """Function to lookup an IP address on VirusTotal and writes the response to a file. If the file write fails, the raw response is printed instead.

    If the API call is successful, the JSON response is written to a file called "ip_lookup.json" and the function returns True.

    If the API call is unsuccessful or the file write fails, the function returns False.

    Args:
        input_ip: The IP address to look up.
        json_dir: The directory to save the JSON response file. Default is "osint_json".
        json_file: The filename of the JSON response file. Default is "ip_lookup.json".

    Returns:
        bool: True if the API call was successful, False otherwise.
    """
    # Set up parameters for the API call
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{input_ip}"
    payload = ""
    headers = {"X-Apikey": vt_api_key}

    # Make the API call
    response = requests.request("GET", url, data=payload, headers=headers)

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


def vt_check_ip(
    response_json_dir: str = "osint_json",
    response_json_file: str = "vt_ip_lookup.json",
) -> dict:
    """Function to check the response from a VirusTotal IP lookup for vendors that detected the IP address as malicious.

    Args:
        response_json_dir: The directory of the JSON response from the VirusTotal IP lookup. Default is "osint_json".
        response_json_file: The filename of the JSON response from the VirusTotal IP lookup. Default is "vt_ip_lookup.json".

    Returns:
        dict: A dictionary containing the vendors that detected the IP address as malicious and number of vendors from the JSON response.
    """
    # Form the file path to read
    response_json_dir_file = os.path.join(response_json_dir, response_json_file)
    with open(response_json_dir_file) as f:
        response = json.load(f)

    # Initialize list of vendors that detected the IP address as malicious
    vendors_detected_malicious = []

    # Print the IP address
    ip = response["data"]["id"]

    # Get total number of vendors based on last_analysis_stats
    total_vendors = (
        response["data"]["attributes"]["last_analysis_stats"]["malicious"]
        + response["data"]["attributes"]["last_analysis_stats"]["suspicious"]
        + response["data"]["attributes"]["last_analysis_stats"]["undetected"]
        + response["data"]["attributes"]["last_analysis_stats"]["harmless"]
        + response["data"]["attributes"]["last_analysis_stats"]["timeout"]
    )

    # Update list of vendors that detected the IP address as malicious
    for vendor in response["data"]["attributes"]["last_analysis_results"]:
        if (
            response["data"]["attributes"]["last_analysis_results"][vendor]["result"]
            == "malicious"
            or response["data"]["attributes"]["last_analysis_results"][vendor]["result"]
            == "malware"
        ):
            vendors_detected_malicious.append(vendor)

    # Set the count of vendors that detected the IP address as malicious
    if vendors_detected_malicious:
        num_vendors_detected_malicious = (
            f"{len(vendors_detected_malicious)}/{total_vendors}"
        )
    else:
        num_vendors_detected_malicious = f"0/{total_vendors}"

    # Return details as a dictionary
    return {
        "ip": ip,
        "vendors_detected_malicious": vendors_detected_malicious,
        "num_vendors_detected_malicious": num_vendors_detected_malicious,
    }


def nice_print_vt_ip_osint(ip_osint: dict) -> None:
    """Function to print the IP OSINT details in a user-friendly format. This is necessary if the user runs this script directly.

    Args:
        ip_osint: A dictionary containing the IP OSINT details from vt_check_ip().

    Returns:
        None
    """
    # Print the IP OSINT details
    print(f"IP Address: {ip_osint["ip"]}")

    # Check for vendors that detected the IP address as malicious
    if ip_osint["vendors_detected_malicious"]:
        print(
            f"The following VT vendors detected this IP Address as malicious: {", ".join(ip_osint["vendors_detected_malicious"])}"
        )
    else:
        print("No VT vendors detected this IP Address as malicious.")

    print(
        f"VT vendors that detected this IP Address as malicious: {ip_osint["num_vendors_detected_malicious"]}"
    )

# File lookup functions

def vt_file_lookup(input_hash: str, json_dir: str = "osint_json", json_file: str = "vt_file_lookup.json") -> bool:
    """Function to lookup a file on VirusTotal and return the response.

    Args:
        input_hash: The hash of the file to look up.
        json_dir: The directory to save the JSON response file. Default is "osint_json".
        json_file: The filename of the JSON response file. Default is "vt_file_lookup.json".

    Returns:
        bool: True if the API call was successful, False otherwise.
    """
    # Set up parameters for the API call
    url = f"https://www.virustotal.com/api/v3/files/{input_hash}"

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


def vt_check_file(
    response_json_dir: str = "osint_json",
    response_json_file: str = "vt_file_lookup.json",
) -> dict:
    """Function to check the response from a VirusTotal file lookup and return the analysis results.
    
    Args:
        response_json_dir: The directory of the JSON response file. Default is "osint_json".
        response_json_file: The filename of the JSON response file. Default is "vt_file_lookup.json".

    Returns:
        dict: The analysis results of the file lookup.
    """
    # Form the file path to read
    response_json_dir_file = os.path.join(response_json_dir, response_json_file)
    with open(response_json_dir_file, "r") as f:
        response = json.load(f)

    # Initialize list of vendors that detected the IP address as malicious
    vendors_detected_malicious = []

    # Get total number of vendors based on last_analysis_stats
    total_vendors = (
        response["data"]["attributes"]["last_analysis_stats"]["malicious"]
        + response["data"]["attributes"]["last_analysis_stats"]["suspicious"]
        + response["data"]["attributes"]["last_analysis_stats"]["undetected"]
        + response["data"]["attributes"]["last_analysis_stats"]["harmless"]
        + response["data"]["attributes"]["last_analysis_stats"]["timeout"]
        + response["data"]["attributes"]["last_analysis_stats"]["confirmed-timeout"]
        + response["data"]["attributes"]["last_analysis_stats"]["failure"]
        + response["data"]["attributes"]["last_analysis_stats"]["type-unsupported"]
    )

    # Update list of vendors that detected the IP address as malicious
    for vendor in response["data"]["attributes"]["last_analysis_results"]:
        if response["data"]["attributes"]["last_analysis_results"][vendor]["category"] == "malicious":
            vendors_detected_malicious.append(vendor)

    # Set the count of vendors that detected the IP address as malicious
    if vendors_detected_malicious:
        num_vendors_detected_malicious = (
            f"{len(vendors_detected_malicious)}/{total_vendors}"
        )
    else:
        num_vendors_detected_malicious = f"0/{total_vendors}"

    # Get the pertinent information from the JSON response
    sha256 = response["data"]["id"],
    meaningful_name = response["data"]["attributes"]["meaningful_name"]
    file_type = response["data"]["attributes"]["type_description"]
    last_analysis_date_iso = unix_timestamp_to_iso(response["data"]["attributes"]["last_analysis_date"], timezone=8)

    # Return details as a dictionary
    return {
        "sha256": sha256,
        "name": meaningful_name,
        "file_type": file_type,
        "last_analysis_date": last_analysis_date_iso,
        "vendors_detected_malicious": vendors_detected_malicious,
        "num_vendors_detected_malicious": num_vendors_detected_malicious,
    }


def nice_print_vt_file_osint(file_osint: dict) -> None:
    """Function to print the VirusTotal file lookup results in a nice format.

    Args:
        file_osint: The dictionary containing the VirusTotal file lookup results.

    Returns:
        None
    """
    print(f"Name: {file_osint['name']}")
    print(f"File Type: {file_osint['file_type']}")
    print(f"Last Analysis Date: {file_osint['last_analysis_date']}")

    # Check for vendors that detected the IP address as malicious
    if file_osint["vendors_detected_malicious"]:
        print(
            f"The following VT vendors detected this file as malicious: {", ".join(file_osint["vendors_detected_malicious"])}"
        )
        print(
            f"VT vendors that detected this file as malicious: {file_osint["num_vendors_detected_malicious"]}"
        )
    else:
        print("No VT vendors detected this file as malicious.")

# Domain lookup functions

def vt_domain_lookup(
    input_domain: str,
    json_dir: str = "osint_json",
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
    response_json_dir: str = "osint_json",
    response_json_file: str = "vt_domain_lookup.json",
) -> dict:
    """Function to check the response from a VirusTotal domain lookup and return the analysis results.

    Args:
        response_json_dir: The directory where the JSON response file is saved. Default is "osint_json".
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
        response["data"]["attributes"]["last_analysis_date"], timezone=8
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
    args = add_argparser_arguments(
        ip=True, malware_file=True, malware_hash=True, domain=True, response_file=True, response_dir=True
    )

    # Retrieve values from the command line arguments
    input_values_dict = vars(args)

    # Perform input validation of IP address and malware hash
    if input_values_dict["ip"]:
        ip_validation = ip_input_validation(input_values_dict["ip"])
        if not ip_validation:
            raise ValueError("Invalid IP address.")
    if input_values_dict["malware_hash"]:
        hash_validation = hash_input_validation(input_values_dict["malware_hash"])
        if not hash_validation:
            raise ValueError("Invalid hash or hash type.")

    # Define mutually exclusive arguments
    operation_fields = ["ip", "malware_file", "malware_hash", "domain"]
    formatted_fields = [f"--{field}" for field in operation_fields]
    mutually_exclusive_fields = [field for field in operation_fields if input_values_dict.get(field)]

    # If none of the mutually exclusive fields are provided, raise an error
    if not mutually_exclusive_fields:
        raise ValueError(f"Please provide one of {', '.join(formatted_fields)}.")

    # If none of the mutually exclusive fields are provided, and only one of response_file or response_dir is provided, raise an error
    elif not mutually_exclusive_fields and (input_values_dict["response_file"] or input_values_dict["response_dir"]) and not (input_values_dict["response_file"] and input_values_dict["response_dir"]):
        raise ValueError("Please provide both --response_file and --response_dir.")

    # If any of the mutually exclusive fields are provided are provided with response_file or response_dir, raise an error. Allow if both response_file and response_dir are provided.
    elif mutually_exclusive_fields and (input_values_dict["response_file"] or input_values_dict["response_dir"]) and not (input_values_dict["response_file"] and input_values_dict["response_dir"]):
        raise ValueError(f"Please provide either --response_file or --response_dir, or one of {', '.join(formatted_fields)}, not both.")

    # If more than one mutually exclusive field is provided, raise an error
    elif len(mutually_exclusive_fields) > 1:
        raise ValueError(f"Please provide only one of {', '.join(formatted_fields)}.")

    # If the IP address is provided, perform the VirusTotal IP lookup
    elif input_values_dict["ip"]:
        lookup_ip_success = False
        # If response_file and response_dir are provided, use them
        if input_values_dict["response_file"] and input_values_dict["response_dir"]:
            lookup_ip_success = vt_ip_lookup(input_values_dict["ip"], input_values_dict["response_dir"], input_values_dict["response_file"])
        # Else, use the default directory and file
        else:
            lookup_ip_success = vt_ip_lookup(input_values_dict["ip"])
        if lookup_ip_success:
            vt_data = vt_check_ip()
            nice_print_vt_ip_osint(vt_data)
        else:
            print("Error with the VirusTotal API call.")

    # If the malware file is provided, hash the file and perform the VirusTotal file lookup
    elif input_values_dict["malware_file"]:
        # Convert the file to a hash
        malware_hash = hash_file(input_values_dict["malware_file"], "sha256")
        print(f"SHA-256 hash of the file: {malware_hash}")
        lookup_file_success = False
        # If response_file and response_dir are provided, use them
        if input_values_dict["response_file"] and input_values_dict["response_dir"]:
            lookup_file_success = vt_file_lookup(malware_hash, input_values_dict["response_dir"], input_values_dict["response_file"])
        # Else, use the default directory and file
        else:
            lookup_file_success = vt_file_lookup(malware_hash)
        if lookup_file_success:
            vt_data = vt_check_file()
            nice_print_vt_file_osint(vt_data)
        else:
            print("Error looking up the file on VirusTotal. The file might not have been uploaded to VirusTotal yet.")

    # If the malware hash is provided, perform the VirusTotal file lookup
    elif input_values_dict["malware_hash"]:
        lookup_file_success = False
        # If response_file and response_dir are provided, use them
        if input_values_dict["response_file"] and input_values_dict["response_dir"]:
            lookup_file_success = vt_file_lookup(input_values_dict["malware_hash"], input_values_dict["response_dir"], input_values_dict["response_file"])
        # Else, use the default directory and file
        else:
            lookup_file_success = vt_file_lookup(input_values_dict["malware_hash"])
        if lookup_file_success:
            vt_data = vt_check_file()
            nice_print_vt_file_osint(vt_data)
        else:
            print("Error looking up the file on VirusTotal. The file might not have been uploaded to VirusTotal yet.")

    # If the domain is provided, perform the VirusTotal domain lookup
    elif input_values_dict["domain"]:
        lookup_domain_success = False
        # If response_file and response_dir are provided, use them
        if input_values_dict["response_file"] and input_values_dict["response_dir"]:
            lookup_domain_success = vt_domain_lookup(input_values_dict["domain"], input_values_dict["response_dir"], input_values_dict["response_file"])
        # Else, use the default directory and file
        else:
            lookup_domain_success = vt_domain_lookup(input_values_dict["domain"])
        if lookup_domain_success:
            vt_data = vt_check_domain()
            nice_print_vt_domain_osint(vt_data)

    # Default else in case I somehow missed a combination of arguments
    else:
        raise ValueError("Please provide one of --ip, --malware_file, --malware_hash, or --domain.")


if __name__ == "__main__":
    main()
