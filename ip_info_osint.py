import argparse
import re
import ipinfo
import json
import os

# Read secrets.json and import the API key
try:
    with open("secrets.json") as f:
        secrets = json.load(f)
        ip_info_api_key = secrets["ip_info_api_key"]
except:
    print(
        "Error reading secrets.json. Please ensure the file exists and the API key is correct."
    )
    exit(1)


def ii_ip_lookup(
    input_ip: str, json_dir: str = "ip_osint_json", json_file: str = "ii_ip_lookup.json"
) -> bool:
    """Function to lookup an IP address on IPinfo and print the response.

    Args:
    input_ip (str): The IP address to look up.
    json_dir (str): The directory to save the JSON response file. Default is "ip_osint_json".
    json_file (str): The filename of the JSON response file. Default is "ii_ip_lookup.json".

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
    except:
        print("Error writing to file, returning raw response instead.")
        print(details.all)
        return False


def ii_check_ip(
    response_json_dir: str = "ip_osint_json",
    response_json_file: str = "ii_ip_lookup.json",
):
    """Function to check the response from a VirusTotal IP lookup for vendors that detected the IP address as malicious.

    Args:
    response_json_dir (str): The directory of the JSON response from the VirusTotal IP lookup. Default is "ip_osint_json".
    response_json_file (str): The filename of the JSON response from the VirusTotal IP lookup. Default is "ii_ip_lookup.json".

    Returns:
    None
    """
    # Form the file path to read
    response_json_dir_file = os.path.join(response_json_dir, response_json_file)
    with open(response_json_dir_file) as f:
        response = json.load(f)

    # Get the city, region, org, country_name from the JSON response
    city = response["city"]
    region = response["region"]
    org = response["org"]
    country_name = response["country_name"]

    # Print the details
    print(f"City: {city}")
    print(f"Region: {region}")
    print(f"Organization: {org}")
    print(f"Country: {country_name}")


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
    # Set up the argument parser
    parser = argparse.ArgumentParser()

    # Add arguments
    parser.add_argument(
        "--ip",
        "-i",
        type=str,
        help="The IP address to look up on ipinfo.",
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

    # Perform input validation
    if ip_address:
        if not regex_ip_verification(ip_address):
            print("Invalid IP address format. Please provide a valid IP address.")
            exit(1)

    # Decision tree for the arguments
    if ip_address and response_file:
        print("Please provide only one of --ip or --response_file.")
        exit(1)
    # If the IP address is provided, perform the ipinfo IP lookup
    elif ip_address:
        lookup_ip_success = False
        lookup_ip_success = ii_ip_lookup(input_ip=ip_address)
        if lookup_ip_success:
            ii_check_ip(response_json_file="ii_ip_lookup.json")
        else:
            print("Error with the ipinfo API call.")
    # If both the response file and directory are provided, use them
    elif response_file and response_dir:
        ii_check_ip(response_json_file=response_file, response_json_dir=response_dir)
    # If only the response file is provided, use the default directory
    elif response_file and not response_dir:
        print(
            "No response directory provided. Using default directory 'ip_osint_json'."
        )
        ii_check_ip(response_json_file=response_file)
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
