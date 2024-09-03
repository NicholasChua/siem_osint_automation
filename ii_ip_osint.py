#!/usr/bin/env python3

import os
import json
import ipinfo

# Internal imports
from common.helper_functions import (
    ip_input_validation,
    retrieve_secrets,
    add_argparser_arguments,
)

# Read .env and import the API key
ip_info_api_key = retrieve_secrets("ip_info_api_key")


def ii_ip_lookup(
    input_ip: str, json_dir: str = "osint_json", json_file: str = "ii_ip_lookup.json"
) -> bool:
    """Function to lookup an IP address on IPinfo and print the response.

    Args:
        input_ip: The IP address to look up.
        json_dir: The directory to save the JSON response file. Default is "osint_json".
        json_file: The filename of the JSON response file. Default is "ii_ip_lookup.json".

    Returns:
        bool: True if the API call was successful, False otherwise.
    """
    # Set up the IPinfo API client
    handler = ipinfo.getHandler(ip_info_api_key)

    # Make the API call
    try:
        details = handler.getDetails(input_ip)
    except:
        print("Error making API call.")
        return False

    # Try to write the JSON response to a file
    try:
        with open(os.path.join(json_dir, json_file), "w") as f:
            json.dump(details.all, f, indent=2)
            return True
    except IOError or OSError:
        print("Error writing to file, returning raw response instead.")
        print(details.all)
        return False
    except:
        print("Unknown error occurred.")
        return False


def ii_check_ip(
    response_json_dir: str = "osint_json",
    response_json_file: str = "ii_ip_lookup.json",
) -> dict:
    """Function to check the response from a VirusTotal IP lookup for vendors that detected the IP address as malicious.

    Args:
        response_json_dir: The directory of the JSON response from the VirusTotal IP lookup. Default is "osint_json".
        response_json_file: The filename of the JSON response from the VirusTotal IP lookup. Default is "ii_ip_lookup.json".

    Returns:
        dict: A dictionary containing the timestamp and details of the IP address from the JSON response.
    """
    # Form the file path to read
    response_json_dir_file = os.path.join(response_json_dir, response_json_file)
    with open(response_json_dir_file) as f:
        response = json.load(f)

    # Get the ip, city, region, org, country_name from the JSON response
    ip = response["ip"]
    city = response["city"]
    region = response["region"]
    org = response["org"]
    country_name = response["country_name"]

    # Return the timestamp and details as a dictionary
    return {
        "ip": ip,
        "city": city,
        "region": region,
        "organization": org,
        "country": country_name,
    }


def nice_print_ii_ip_osint(ip_osint: dict) -> None:
    """Function to print the IP address details in a nice format. This is necessary if the user runs this script directly.

    Args:
        ip_osint: A dictionary containing the timestamp and details of the IP address from the JSON response.

    Returns:
        None
    """
    # Print the IP address details
    print(f"IP Address: {ip_osint["ip"]}")
    print(f"City: {ip_osint["city"]}")
    print(f"Region: {ip_osint["region"]}")
    print(f"Organization: {ip_osint["organization"]}")
    print(f"Country: {ip_osint["country"]}")


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
            lookup_ip_success = ii_ip_lookup(input_ip=input_values_dict["ip"], json_dir=input_values_dict["response_dir"], json_file=input_values_dict["response_file"])
        # Else, use the default directory and file
        else:
            lookup_ip_success = ii_ip_lookup(input_ip=input_values_dict["ip"])
        if lookup_ip_success:
            ii_data = ii_check_ip(response_json_file="ii_ip_lookup.json")
            nice_print_ii_ip_osint(ii_data)
        else:
            print("Error with the ipinfo API call.")


if __name__ == "__main__":
    main()
