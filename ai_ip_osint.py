#!/usr/bin/env python3

import os
import json
import requests

# Internal imports
from common.helper_functions import (
    ip_input_validation,
    retrieve_secrets,
    add_argparser_arguments,
)

# Read .env and import the API key
apidb_key = retrieve_secrets("aipdb_key")


def ai_ip_lookup(
    input_ip: str, json_dir: str = "osint_json", json_file: str = "ai_ip_lookup.json"
) -> bool:
    """Function to lookup an IP address on AbuseIPDB and writes the response to a file. If the file write fails, the raw response is printed instead.

    If the API call is successful, the JSON response is written to a file called "ai_ip_lookup.json" and the function returns True.

    If the API call is unsuccessful or the file write fails, the function returns False.

    Args:
        input_ip: The IP address to look up.
        json_dir: The directory to save the JSON response file. Default is "osint_json".
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
    response_json_dir: str = "osint_json",
    response_json_file: str = "ai_ip_lookup.json",
) -> dict:
    """Function to check the response from an AbuseIPDB IP lookup for the abuse confidence score.

    Args:
        response_json_dir: The directory of the JSON response from the AbuseIPDB IP lookup. Default is "osint_json".
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
    input_values_dict = vars(args)

    # Perform input validation of IP address
    if input_values_dict["ip"]:
        ip_validation = ip_input_validation(input_values_dict["ip"])
        if not ip_validation:
            raise ValueError("Invalid IP address.")

    # If the IP address and response_file are provided, raise an error
    if input_values_dict["ip"] and input_values_dict["response_file"]:
        raise ValueError("Please provide only one of --ip or --response_file.")

    # If only one of response_file or response_dir is provided, raise an error
    elif (input_values_dict["response_file"] or input_values_dict["response_dir"]) and not (input_values_dict["response_file"] and input_values_dict["response_dir"]):
        raise ValueError("Please provide both --response_file and --response_dir.")

    # If the IP address is provided, perform the ipinfo IP lookup
    elif input_values_dict["ip"]:
        lookup_ip_success = False
        # If response_file and response_dir are provided, use them
        if input_values_dict["response_file"] and input_values_dict["response_dir"]:
            lookup_ip_success = ai_ip_lookup(input_ip=input_values_dict["ip"], json_dir=input_values_dict["response_dir"], json_file=input_values_dict["response_file"])
        # Else, use the default directory and file
        else:
            lookup_ip_success = ai_ip_lookup(input_ip=input_values_dict["ip"])
        if lookup_ip_success:
            ai_data = ai_check_ip(response_json_file="ai_ip_lookup.json")
            nice_print_ai_ip_osint(ai_data)
        else:
            print("Error with the AbuseIPDB API call.")


if __name__ == "__main__":
    main()
