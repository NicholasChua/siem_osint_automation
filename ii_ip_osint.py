import argparse
import ipaddress
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
    input_ip: The IP address to look up.
    json_dir: The directory to save the JSON response file. Default is "ip_osint_json".
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
    except:
        print("Error writing to file, returning raw response instead.")
        print(details.all)
        return False


def ii_check_ip(
    response_json_dir: str = "ip_osint_json",
    response_json_file: str = "ii_ip_lookup.json",
) -> dict:
    """Function to check the response from a VirusTotal IP lookup for vendors that detected the IP address as malicious.

    Args:
    response_json_dir: The directory of the JSON response from the VirusTotal IP lookup. Default is "ip_osint_json".
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

    # Return the timestamp and details as a dictionary with the key ipinfo_ip_osint
    return {
        "ip": ip,
        "city": city,
        "region": region,
        "organization": org,
        "country": country_name,
    }


def nice_print_ii_ip_osint(ip_osint: dict) -> None:
    """Function to print the IP address details in a nice format.

    Args:
    ip_osint: A dictionary containing the timestamp and details of the IP address from the JSON response.

    Returns:
    None
    """
    # Print the IP address details
    print(f"IP Address: {ip_osint['ipinfo_ip_osint']['ip']}")
    print(f"City: {ip_osint['ipinfo_ip_osint']['city']}")
    print(f"Region: {ip_osint['ipinfo_ip_osint']['region']}")
    print(f"Organization: {ip_osint['ipinfo_ip_osint']['organization']}")
    print(f"Country: {ip_osint['ipinfo_ip_osint']['country']}")


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
    # If the IP address is provided, perform the ipinfo IP lookup
    elif ip_address:
        lookup_ip_success = False
        lookup_ip_success = ii_ip_lookup(input_ip=ip_address)
        if lookup_ip_success:
            ii_data = ii_check_ip(response_json_file="ii_ip_lookup.json")
            nice_print_ii_ip_osint(ii_data)
        else:
            print("Error with the ipinfo API call.")
    # If both the response file and directory are provided, use them
    elif response_file and response_dir:
        ii_data = ii_check_ip(response_json_file=response_file, response_json_dir=response_dir)
        nice_print_ii_ip_osint(ii_data)
    # If only the response file is provided, use the default directory
    elif response_file and not response_dir:
        print(
            "No response directory provided. Using default directory 'ip_osint_json'."
        )
        ii_data = ii_check_ip(response_json_file=response_file)
        print(ii_data)
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
