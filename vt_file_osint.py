import json
import os
import requests

# Internal imports
from common.helper_functions import (
    retrieve_secrets,
    hash_file,
    unix_timestamp_to_iso,
    add_argparser_arguments,
)

# Read secrets.json and import the API key
vt_api_key = retrieve_secrets("vt_api_key")


def vt_file_lookup(input_hash: str, json_dir: str = "ip_osint_json", json_file: str = "vt_file_lookup.json") -> bool:
    """Function to lookup a file on VirusTotal and return the response.

    Args:
        input_hash: The hash of the file to look up.
        json_dir: The directory to save the JSON response file. Default is "ip_osint_json".
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
    response_json_dir: str = "ip_osint_json",
    response_json_file: str = "vt_file_lookup.json",
) -> dict:
    """Function to check the response from a VirusTotal file lookup and return the analysis results.
    
    Args:
        response_json_dir: The directory of the JSON response file. Default is "ip_osint_json".
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
    threat_label = response["data"]["attributes"]["popular_threat_classification"]["suggested_threat_label"]
    file_type = response["data"]["attributes"]["type_description"]
    last_analysis_date_iso = unix_timestamp_to_iso(response["data"]["attributes"]["last_analysis_date"])

    # Return details as a dictionary
    return {
        "sha256": sha256,
        "threat_label": threat_label,
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
    print(f"Threat Label: {file_osint['threat_label']}")
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


def main():
    # Add arguments to the ArgumentParser object
    args = add_argparser_arguments(response_file=True, response_dir=True, malware_file=True, malware_hash=True)

    # Retrieve values from the command line arguments
    response_file = args.response_file
    response_dir = args.response_dir
    malware_file = args.malware_file
    malware_hash = args.malware_hash

    # Perform input validation of malware hash for sha256, sha1, and md5
    if malware_hash:
        if len(malware_hash) == 64:
            # Valid SHA-256 hash
            pass
        elif len(malware_hash) == 40:
            # Valid SHA-1 hash
            pass
        elif len(malware_hash) == 32:
            # Valid MD5 hash
            pass
        else:
            raise ValueError("The hash provided is not a valid SHA-256, SHA-1, or MD5 hash.")

    # Decision tree for the arguments
    if malware_file and malware_hash:
        raise ValueError("Please provide only one of --malware_file or --malware_hash.")
    # If the malware file is provided, hash the file and perform the VirusTotal file lookup
    elif malware_file:
        # Convert the file to a hash
        malware_hash = hash_file(malware_file, "sha256")
        print(f"SHA-256 hash of the file: {malware_hash}")
        lookup_file_success = False
        lookup_file_success = vt_file_lookup(malware_hash)
        if lookup_file_success:
            vt_data = vt_check_file()
            nice_print_vt_file_osint(vt_data)
        else:
            print("Error looking up the file on VirusTotal. The file might not have been uploaded to VirusTotal yet.")
    # If the malware hash is provided, perform the VirusTotal file lookup
    elif malware_hash:
        lookup_file_success = False
        lookup_file_success = vt_file_lookup(malware_hash)
        if lookup_file_success:
            vt_data = vt_check_file()
            nice_print_vt_file_osint(vt_data)
        else:
            print("Error looking up the file on VirusTotal. The file might not have been uploaded to VirusTotal yet.")
    # If both the response file and directory are provided, use them
    elif response_file and response_dir:
        vt_data = vt_check_file(
            response_json_file=response_file, response_json_dir=response_dir
        )
        nice_print_vt_file_osint(vt_data)
    # If only the response file is provided, use the default directory
    elif response_file and not response_dir:
        print(
            "No response directory provided. Using default directory 'ip_osint_json'."
        )
        vt_data = vt_check_file(response_json_file=response_file)
        nice_print_vt_file_osint(vt_data)
    # If only the response directory is provided, print an error
    elif response_dir and not response_file:
        raise ValueError(
            "Please provide the response file (--response_file <file>) with the response directory."
        )
    # If no or invalid arguments are provided, print an error
    else:
        raise ValueError("Please provide one of --malware_file or --malware_hash.")


if __name__ == "__main__":
    main()
