#!/usr/bin/env python3

import vt_osint as vt
import ii_ip_osint as ii
import ai_ip_osint as ai

# Internal imports
from common.helper_functions import (
    add_argparser_arguments,
    calculate_iso_time,
    hash_file,
    hash_input_validation,
    ip_input_validation,
)


def format_comment(
    vt_ip_osint: dict = {},
    ii_ip_osint: dict = {},
    ai_ip_osint: dict = {},
    vt_file_osint: dict = {},
    vt_domain_osint: dict = {},
) -> str:
    """Function to format the OSINT details from VirusTotal, ipinfo.io and AbuseIPDB into a comment.

    Args:
    vt_ip_osint: A dictionary containing the IP OSINT details from vt_check_ip(). Default is an empty dictionary.
    ii_ip_osint: A dictionary containing the IP OSINT details from ii_check_ip(). Default is an empty dictionary.
    ai_ip_osint: A dictionary containing the IP OSINT details from ai_check_ip(). Default is an empty dictionary.
    vt_file_osint: A dictionary containing the file OSINT details from vt_check_file(). Default is an empty dictionary.
    vt_domain_osint: A dictionary containing the domain OSINT details from vt_check_domain(). Default is an empty dictionary.

    Returns:
    str: A formatted comment with the OSINT details. Each detail is on a new line with a '- ' prefix and ends with a newline character.
    """
    # Initialize the comment list
    comment = ["SOAP_auto_analysis:"]

    # Get the current timestamp in ISO 8601 format and print it
    timestamp = calculate_iso_time(timestamp_format=1, timezone=8)["current_time"]

    # Initialize the comment list with the timestamp
    comment += [f"- Analyzed at {timestamp}."]

    # Check for presence of data within all dictionaries
    if (
        vt_ip_osint == {}
        and ii_ip_osint == {}
        and ai_ip_osint == {}
        and vt_file_osint == {}
        and vt_domain_osint == {}
    ):
        raise Exception("There is no data.")

    # Process each dictionary and add the details to the comment list
    if vt_ip_osint:
        try:
            comment += [
                f"- VirusTotal Link: https://www.virustotal.com/gui/ip-address/{vt_ip_osint['ip']}"
            ]

            # Check for vendors that detected the IP address as malicious
            if vt_ip_osint["vendors_detected_malicious"]:
                comment += [
                    f"- IP flagged as potential threat by {vt_ip_osint['num_vendors_detected_malicious']} VirusTotal vendors: {', '.join(vt_ip_osint['vendors_detected_malicious'])}"
                ]
            else:
                comment += ["- IP is clean in VirusTotal."]
        except KeyError:
            print("Missing key in vt_ip_osint. Assuming it is empty.")
            pass
        except:
            raise Exception("Error in vt_ip_osint.")

    if ii_ip_osint:
        try:
            comment += [f"- ipinfo Link: https://ipinfo.io/{ii_ip_osint['ip']}"]
            comment += [
                f"- IP Geolocation is in country {ii_ip_osint['country']}, region {ii_ip_osint['region']}, city {ii_ip_osint['city']}."
            ]
            comment += [f"- IP belongs to: {ii_ip_osint['organization']}"]
        except KeyError:
            print("Missing key in ii_ip_osint. Assuming it is empty.")
            pass
        except:
            raise Exception("Error in ii_ip_osint.")

    if ai_ip_osint:
        try:
            comment += [
                f"- AbuseIPDB Link: https://www.abuseipdb.com/check/{ai_ip_osint['ip']}"
            ]
            comment += [
                f"- Abuse Confidence Score: {ai_ip_osint['abuseConfidenceScore']}"
            ]

            # Print an appropriate message based on the isTor value
            if ai_ip_osint["isTor"]:
                comment += ["- IP is a Tor exit node."]
            else:
                comment += ["- IP is not a Tor exit node."]

        except KeyError:
            print("Missing key in ai_ip_osint. Assuming it is empty.")
            pass
        except:
            raise Exception("Error in ai_ip_osint.")

    if vt_file_osint:
        try:
            file_hash = "".join(vt_file_osint["sha256"])
            comment += [
                f"- VirusTotal Link: https://www.virustotal.com/gui/file/{file_hash}"
            ]
            comment += [f"- Name: {vt_file_osint['name']}"]
            comment += [f"- File Type: {vt_file_osint['file_type']}"]
            # Check for vendors that detected the IP address as malicious
            if vt_file_osint["vendors_detected_malicious"]:
                comment += [
                    f"- File flagged as potential threat by {vt_file_osint['num_vendors_detected_malicious']} VirusTotal vendors: {', '.join(vt_file_osint['vendors_detected_malicious'])}"
                ]
            else:
                comment += ["- File is clean in VirusTotal."]
        except KeyError:
            print("Missing key in vt_file_osint. Assuming it is empty.")
            pass
        except:
            raise Exception("Error in vt_file_osint.")

    if vt_domain_osint:
        try:
            comment += [
                f"- VirusTotal Link: https://www.virustotal.com/gui/domain/{vt_domain_osint['domain']}"
            ]

            if vt_domain_osint["ipv4_addresses"]:
                comment += [
                    f"- IPv4 Addresses: {', '.join(vt_domain_osint['ipv4_addresses'])}"
                ]
            else:
                comment += ["- No IPv4 addresses found."]

            if vt_domain_osint["ipv6_addresses"]:
                comment += [
                    f"- IPv6 Addresses: {', '.join(vt_domain_osint['ipv6_addresses'])}"
                ]
            else:
                comment += ["- No IPv6 addresses found."]

            if vt_domain_osint["alternate_domains"]:
                comment += [
                    f"- Alternate Domains: {', '.join(vt_domain_osint['alternate_domains'])}"
                ]
            else:
                comment += ["- No alternate domains found."]

            # Check for vendors that detected the domain as malicious
            if vt_domain_osint["vendors_detected_malicious"]:
                comment += [
                    f"- Domain flagged as potential threat by {vt_domain_osint['num_vendors_detected_malicious']} VirusTotal vendors: {', '.join(vt_domain_osint['vendors_detected_malicious'])}"
                ]
            else:
                comment += ["- Domain is clean in VirusTotal."]
        except KeyError:
            print("Missing key in vt_domain_osint. Assuming it is empty.")
            pass
        except:
            raise Exception("Error in vt_domain_osint.")

    # Convert the comment list to a string
    commentStr = "\n".join(comment)

    return commentStr


def combined_ip_osint(input_ip: str) -> str:
    """Function to use format_comment to combine the IP OSINT details from VirusTotal, ipinfo.io and AbuseIPDB into a comment.

    Args:
        input_ip: The IP address to lookup.

    Returns:
        str: A formatted comment with the IP OSINT details. Each detail is on a new line with a '- ' prefix and ends with a newline character.
    """
    # Perform VT IP lookup
    try:
        success_vt = vt.vt_ip_lookup(input_ip=input_ip)
        if success_vt:
            vt_ip_osint = vt.vt_check_ip()
        else:
            print("Error looking up the IP on VirusTotal.")
            vt_ip_osint = {}
    except:
        print("Error looking up the IP on VirusTotal.")
        vt_ip_osint = {}

    # Perform ipinfo.io IP lookup
    try:
        success_ii = ii.ii_ip_lookup(input_ip=input_ip)
        if success_ii:
            ii_ip_osint = ii.ii_check_ip()
        else:
            print("Error looking up the IP on ipinfo.io.")
            ii_ip_osint = {}
    except:
        print("Error looking up the IP on ipinfo.io.")
        ii_ip_osint = {}

    # Perform AbuseIPDB IP lookup
    try:
        success_ai = ai.ai_ip_lookup(input_ip=input_ip)
        if success_ai:
            ai_ip_osint = ai.ai_check_ip()
        else:
            print("Error looking up the IP on AbuseIPDB.")
            ai_ip_osint = {}
    except:
        print("Error looking up the IP on AbuseIPDB.")
        ai_ip_osint = {}

    # Pass the dictionaries to the format_comment function
    comment = format_comment(
        vt_ip_osint=vt_ip_osint, ii_ip_osint=ii_ip_osint, ai_ip_osint=ai_ip_osint
    )

    # Return the comment
    return comment


def malware_osint_comment(malware_file: str = None, malware_hash: str = None) -> str:
    """Function to use format_comment to combine the file OSINT details from VirusTotal into a comment.

    Args:
        malware_file: The malware file to lookup. Default is None.
        malware_hash: The malware hash to lookup. Default is None.

    Returns:
        str: A formatted comment with the file OSINT details. Each detail is on a new line with a '- ' prefix and ends with a newline character.    
    """
    # Convert the malware file to a SHA-256 hash first if malware_file is provided
    if malware_file and not malware_hash:
        malware_hash = hash_file(malware_file, "sha256")

    # Perform the VirusTotal file lookup
    success = vt.vt_file_lookup(input_hash=malware_hash)
    if success:
        vt_file_osint = vt.vt_check_file()
        comment = format_comment(vt_file_osint=vt_file_osint)
    else:
        comment = "Error looking up the file on VirusTotal. The file might not have been uploaded to VirusTotal yet."

    return comment


def domain_osint_comment(input_domain: str) -> str:
    """Function to use format_comment to combine the domain OSINT details from VirusTotal into a comment.

    Args:
        input_domain: The domain to lookup.

    Returns:
        str: A formatted comment with the domain OSINT details. Each detail is on a new line with a '- ' prefix and ends with a newline character.
    """
    # Perform the VirusTotal domain lookup
    success = vt.vt_domain_lookup(input_domain=input_domain)
    if success:
        vt_domain_osint = vt.vt_check_domain()
        comment = format_comment(vt_domain_osint=vt_domain_osint)
    else:
        comment = "Error looking up the domain on VirusTotal."

    return comment


def main():
    # Set up argparser with arguments
    args = add_argparser_arguments(
        ip=True,
        malware_file=True,
        malware_hash=True,
        domain=True,
        response_file=False,
        response_dir=False,
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
    mutually_exclusive_fields = [
        field for field in operation_fields if input_values_dict.get(field)
    ]

    # If none of the mutually exclusive fields are provided, raise an error
    if not mutually_exclusive_fields:
        raise ValueError(f"Please provide one of {', '.join(formatted_fields)}.")

    # If more than one mutually exclusive field is provided, raise an error
    elif len(mutually_exclusive_fields) > 1:
        raise ValueError(f"Please provide only one of {', '.join(formatted_fields)}.")

    # If the IP address is provided, perform the IP lookups
    elif input_values_dict["ip"]:
        comment = combined_ip_osint(input_ip=input_values_dict["ip"])
        print(comment)

    # If the malware file or hash is provided, perform the VirusTotal file lookup
    elif input_values_dict["malware_file"] or input_values_dict["malware_hash"]:
        comment = malware_osint_comment(
            malware_file=input_values_dict["malware_file"],
            malware_hash=input_values_dict["malware_hash"],
        )
        print(comment)

    # If the domain is provided, perform the VirusTotal domain lookup
    elif input_values_dict["domain"]:
        comment = domain_osint_comment(input_domain=input_values_dict["domain"])
        print(comment)

    # Default case if none of the above conditions are met
    else:
        raise ValueError(f"Please provide one of {', '.join(formatted_fields)}.")


if __name__ == "__main__":
    main()
