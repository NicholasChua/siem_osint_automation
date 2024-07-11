import json
import requests
import argparse
import os
import re

# Read secrets.json and import the API key
try:
    with open("secrets.json") as f:
        secrets = json.load(f)
        vt_api_key = secrets["vt_api_key"]
except:
    print("Error reading secrets.json. Please ensure the file exists and the API key is correct.")
    exit(1)


def vt_ip_lookup(input_ip: str, json_dir: str = "ip_osint_json", json_file: str = "vt_ip_lookup.json") -> bool:
    """Function to lookup an IP address on VirusTotal and writes the response to a file. If the file write fails, the raw response is printed instead.

    If the API call is successful, the JSON response is written to a file called "ip_lookup.json" and the function returns True.

    If the API call is unsuccessful or the file write fails, the function returns False.

    Args:
    input_ip (str): The IP address to look up.
    json_dir (str): The directory to save the JSON response file. Default is "ip_osint_json".
    json_file (str): The filename of the JSON response file. Default is "ip_lookup.json".

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


def vt_check_ip(response_json_dir: str = "ip_osint_json", response_json_file: str = "vt_ip_lookup.json"):
    """Function to check the response from a VirusTotal IP lookup for vendors that detected the IP address as malicious.

    Args:
    response_json_dir (str): The directory of the JSON response from the VirusTotal IP lookup. Default is "ip_osint_json".
    response_json_file (str): The filename of the JSON response from the VirusTotal IP lookup. Default is "vt_ip_lookup.json".

    Returns:
    None
    """
    # Form the file path to read
    response_json_dir_file = os.path.join(response_json_dir, response_json_file)
    with open(response_json_dir_file) as f:
        response = json.load(f)

    # Initialize list of vendors that detected the IP address as malicious
    vendors_detected_malicious = []

    print(f"IP Address: {response['data']['id']}")

    # Update list of vendors that detected the IP address as malicious
    for vendor in response["data"]["attributes"]["last_analysis_results"]:
        if (
            response["data"]["attributes"]["last_analysis_results"][vendor]["result"]
            == "malicious"
        ):
            vendors_detected_malicious.append(vendor)

    # Print the list of vendors that detected the IP address as malicious
    if vendors_detected_malicious:
        print(
            f"The following VT vendors detected this IP address as malicious: {', '.join(vendors_detected_malicious)}"
        )
    else:
        print("No VT vendors detected this IP address as malicious.")


def regex_ip_verification(input_ip: str) -> bool:
    """Helper function to verify that the input IP address is in the correct format using regex.

    Args:
    input_ip (str): The IP address to verify.

    Returns:
    bool: True if the IP address is in the correct format, False otherwise.
    """
    # Regular expression for an IP address
    ip_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    # Check if the input IP address matches the regular expression
    if re.match(ip_regex, input_ip):
        return True
    else:
        return False


def main():
    # Initialize parser
    parser = argparse.ArgumentParser()

    # Add arguments
    parser.add_argument("--ip", "-i", type=str, help="The IP address to look up on VirusTotal.", required=False)
    parser.add_argument("--response_file", "-f", type=str, help="The filename of the JSON response from the IP lookup.", required=False)
    parser.add_argument("--response_dir", "-d", type=str, help="The directory of the JSON response from the IP lookup. Used with --response_file", required=False)

    # Parse arguments
    args = parser.parse_args()
    ip_address = args.ip
    response_file = args.response_file
    response_dir = args.response_dir

    # Perform input validation
    if ip_address:
        if not regex_ip_verification(ip_address):
            print("Invalid IP address format. Please provide a valid IP address.")
            exit(1)

    # Decision tree for the arguments
    if ip_address and response_file:
        print("Please provide only one of --ip or --response_file.")
        exit(1)
    # If the IP address is provided, perform the VirusTotal IP lookup
    elif ip_address:
        lookup_ip_success = False
        lookup_ip_success = vt_ip_lookup(input_ip = ip_address)
        if lookup_ip_success:
            vt_check_ip(response_json_file = "vt_ip_lookup.json")
        else:
            print("Error with the VirusTotal API call.")
    # If both the response file and directory are provided, use them
    elif response_file and response_dir:
        vt_check_ip(response_json_file = response_file, response_json_dir = response_dir)
    # If only the response file is provided, use the default directory
    elif response_file and not response_dir:
        print("No response directory provided. Using default directory 'ip_osint_json'.")
        vt_check_ip(response_json_file = response_file)
    # If only the response directory is provided, print an error
    elif response_dir and not response_file:
        print("Please provide the response file (--response_file <file>) with the response directory.")
        exit(1)
    # If no or invalid arguments are provided, print an error
    else:
        print("Please provide one of --ip or --response_file.")
        exit(1)


if __name__ == "__main__":
    main()
