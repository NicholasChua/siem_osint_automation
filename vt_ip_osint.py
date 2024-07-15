import json
import requests
import argparse
import os
import ipaddress

# Read secrets.json and import the API key
try:
    with open("secrets.json") as f:
        secrets = json.load(f)
        vt_api_key = secrets["vt_api_key"]
except:
    print(
        "Error reading secrets.json. Please ensure the file exists and the API key is correct."
    )
    exit(1)


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
        except:
            print("Error writing to file, returning raw response instead.")
            print(response.text())
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
        num_vendors_detected_malicious = (f"{len(vendors_detected_malicious)}/{total_vendors}")
    else:
        num_vendors_detected_malicious = (f"0/{total_vendors}")

    # Return details as a dictionary with key virustotal_ip_osint
    return {
        "virustotal_ip_osint": {
            "ip": ip,
            "vendors_detected_malicious": vendors_detected_malicious,
            "num_vendors_detected_malicious": num_vendors_detected_malicious,
        },
    }


def nice_print_vt_ip_osint(ip_osint: dict) -> None:
    """Function to print the IP OSINT details in a user-friendly format. This is necessary if the user runs this script directly.

    Args:
    ip_osint: A dictionary containing the IP OSINT details from vt_check_ip().

    Returns:
    None
    """
    # Print the IP OSINT details
    print(f"IP Address: {ip_osint['virustotal_ip_osint']['ip']}")
    
    # Check for vendors that detected the IP address as malicious
    if ip_osint['virustotal_ip_osint']['vendors_detected_malicious']:
        print(
            f"The following VT vendors detected this IP Address as malicious: {', '.join(ip_osint['virustotal_ip_osint']['vendors_detected_malicious'])}"
        )
    else:
        print("No VT vendors detected this IP Address as malicious.")

    print(
        f"VT vendors that detected this IP Address as malicious: {ip_osint['virustotal_ip_osint']['num_vendors_detected_malicious']}"
    )


def main():
    # Initialize parser
    parser = argparse.ArgumentParser()

    # Add arguments
    parser.add_argument(
        "--ip",
        "-i",
        type=str,
        help="The IP address to look up on VirusTotal.",
        required=False,
    )
    parser.add_argument(
        "--response_file",
        "-f",
        type=str,
        help="The filename of the JSON response from the IP lookup.",
        required=False,
    )
    parser.add_argument(
        "--response_dir",
        "-d",
        type=str,
        help="The directory of the JSON response from the IP lookup. Used with --response_file",
        required=False,
    )

    # Parse arguments
    args = parser.parse_args()
    ip_address = args.ip
    response_file = args.response_file
    response_dir = args.response_dir

    # Perform input validation of IP address using built-in ipaddress module
    if ip_address:
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            print("Invalid IP address. Please provide a valid IP address.")
            exit(1)

    # Decision tree for the arguments
    if ip_address and response_file:
        print("Please provide only one of --ip or --response_file.")
        exit(1)
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
        vt_data = vt_check_ip(response_json_file=response_file, response_json_dir=response_dir)
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
        print(
            "Please provide the response file (--response_file <file>) with the response directory."
        )
        exit(1)
    # If no or invalid arguments are provided, print an error
    else:
        print("Please provide one of --ip or --response_file.")
        exit(1)


if __name__ == "__main__":
    main()
