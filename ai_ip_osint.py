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
apidb_key = retrieve_secrets("aipdb_key")


def ai_ip_lookup(
    input_ip: str, json_dir: str = "ip_osint_json", json_file: str = "ai_ip_lookup.json"
) -> bool:
    """Function to lookup an IP address on AbuseIPDB and writes the response to a file. If the file write fails, the raw response is printed instead.

    If the API call is successful, the JSON response is written to a file called "ai_ip_lookup.json" and the function returns True.

    If the API call is unsuccessful or the file write fails, the function returns False.

    Args:
    input_ip: The IP address to look up.
    json_dir: The directory to save the JSON response file. Default is "ip_osint_json".
    json_file: The filename of the JSON response file. Default is "ai_ip_lookup.json".

    Returns:
    bool: True if the API call was successful, False otherwise.
    """
    # Set up parameters for the API call
    url = f"https://api.abuseipdb.com/api/v2/check"
    querystring = {"ipAddress": input_ip, "maxAgeInDays": "90"}
    headers = {"Accept": "application/json", "Key": apidb_key}

    # Make the API call
    response = requests.request(
        method="GET", url=url, headers=headers, params=querystring
    )

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


def ai_check_ip(
    response_json_dir: str = "ip_osint_json",
    response_json_file: str = "ai_ip_lookup.json",
) -> dict:
    """Function to check the response from an AbuseIPDB IP lookup for the abuse confidence score.

    Args:
    response_json_dir: The directory of the JSON response from the AbuseIPDB IP lookup. Default is "ip_osint_json".
    response_json_file: The filename of the JSON response from the AbuseIPDB IP lookup. Default is "ai_ip_lookup.json".

    Returns:
    dict: The abuse confidence score from the AbuseIPDB IP lookup.
    """
    # Form the file path to read
    response_json_dir_file = os.path.join(response_json_dir, response_json_file)
    with open(response_json_dir_file) as f:
        response = json.load(f)

    # Get the ip, abuse confidence score, isTor from the JSON response
    ip = response["data"]["ipAddress"]
    abuse_confidence_score = response["data"]["abuseConfidenceScore"]
    is_tor = response["data"]["isTor"]

    # Return the details as a dictionary
    return {"ip": ip, "abuseConfidenceScore": abuse_confidence_score, "isTor": is_tor}


def nice_print_ai_ip_osint(ip_osint: dict) -> None:
    """Function to print the IP address details in a nice format. This is necessary if the user runs this script directly.

    Args:
    ip_osint: A dictionary containing the details of this IP address from the JSON response.

    Returns:
    None
    """
    # Print the IP address details
    print(f"IP Address: {ip_osint["ip"]}")
    print(f"Abuse Confidence Score: {ip_osint["abuseConfidenceScore"]}")
    print(f"Is Tor: {ip_osint["isTor"]}")


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
    # If the IP address is provided, perform the ipinfo IP lookup
    elif ip_address:
        lookup_ip_success = False
        lookup_ip_success = ai_ip_lookup(input_ip=ip_address)
        if lookup_ip_success:
            ai_data = ai_check_ip(response_json_file="ai_ip_lookup.json")
            nice_print_ai_ip_osint(ai_data)
        else:
            print("Error with the AbuseIPDB API call.")
    # If both the response file and directory are provided, use them
    elif response_file and response_dir:
        ai_data = ai_check_ip(
            response_json_file=response_file, response_json_dir=response_dir
        )
        nice_print_ai_ip_osint(ai_data)
    # If only the response file is provided, use the default directory
    elif response_file and not response_dir:
        print(
            "No response directory provided. Using default directory 'ip_osint_json'."
        )
        ai_data = ai_check_ip(response_json_file=response_file)
        nice_print_ai_ip_osint(ai_data)
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
