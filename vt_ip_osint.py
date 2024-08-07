import os
import json
import requests
import ipaddress

# Internal imports
from common.helper_functions import (
    retrieve_secrets,
    add_argparser_arguments,
)

# Read secrets.json and import the API key
vt_api_key = retrieve_secrets("vt_api_key")


def vt_ip_lookup(
    input_ip: str, json_dir: str = "ip_osint_json", json_file: str = "vt_ip_lookup.json"
) -> bool:
    """Function to lookup an IP address on VirusTotal and writes the response to a file. If the file write fails, the raw response is printed instead.

    If the API call is successful, the JSON response is written to a file called "ip_lookup.json" and the function returns True.

    If the API call is unsuccessful or the file write fails, the function returns False.

    Args:
        input_ip: The IP address to look up.
        json_dir: The directory to save the JSON response file. Default is "ip_osint_json".
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
    response_json_dir: str = "ip_osint_json",
    response_json_file: str = "vt_ip_lookup.json",
) -> dict:
    """Function to check the response from a VirusTotal IP lookup for vendors that detected the IP address as malicious.

    Args:
        response_json_dir: The directory of the JSON response from the VirusTotal IP lookup. Default is "ip_osint_json".
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


def main():
    # Set up argparser with arguments
    args = add_argparser_arguments(ip=True, response_file=True, response_dir=True)

    # Retrieve values from the command line arguments
    ip_address = args.ip
    response_file = args.response_file
    response_dir = args.response_dir

    # Perform input validation of IP address using built-in ipaddress module
    if ip_address:
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            raise ValueError("Invalid IP address. Please provide a valid IP address.")

    # Decision tree for the arguments
    if ip_address and response_file:
        raise ValueError("Please provide only one of --ip or --response_file.")
    # If the IP address is provided, perform the VirusTotal IP lookup
    elif ip_address:
        lookup_ip_success = False
        lookup_ip_success = vt_ip_lookup(input_ip=ip_address)
        if lookup_ip_success:
            vt_data = vt_check_ip(response_json_file="vt_ip_lookup.json")
            nice_print_vt_ip_osint(vt_data)
        else:
            print("Error with the VirusTotal API call.")
    # If both the response file and directory are provided, use them
    elif response_file and response_dir:
        vt_data = vt_check_ip(
            response_json_file=response_file, response_json_dir=response_dir
        )
        nice_print_vt_ip_osint(vt_data)
    # If only the response file is provided, use the default directory
    elif response_file and not response_dir:
        print(
            "No response directory provided. Using default directory 'ip_osint_json'."
        )
        vt_data = vt_check_ip(response_json_file=response_file)
        nice_print_vt_ip_osint(vt_data)
    # If only the response directory is provided, print an error
    elif response_dir and not response_file:
        raise ValueError(
            "Please provide the response file (--response_file <file>) with the response directory."
        )
    # If no or invalid arguments are provided, print an error
    else:
        raise ValueError("Please provide one of --ip or --response_file.")


if __name__ == "__main__":
    main()
