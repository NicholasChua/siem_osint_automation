import datetime
import ipaddress
import vt_ip_osint as vti
import ii_ip_osint as ii
import ai_ip_osint as ai
import vt_file_osint as vtf
import vt_domain_osint as vtd


# Internal imports
from common.helper_functions import (
    add_argparser_arguments,
    hash_file,
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
    timestamp = datetime.datetime.now(
        datetime.timezone(datetime.timedelta(hours=8))
    ).isoformat()

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
            comment += [
                f"- VirusTotal Link: https://www.virustotal.com/gui/file/{vt_file_osint['sha256']}"
            ]
            comment += [f"- Threat Label: {vt_file_osint['threat_label']}"]
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
    ip_address = args.ip
    malware_file = args.malware_file
    malware_hash = args.malware_hash
    domain = args.domain

    # Perform input validation of IP address using built-in ipaddress module
    if ip_address:
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            print("Invalid IP address. Please provide a valid IP address.")
            exit(1)

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
            raise ValueError(
                "The hash provided is not a valid SHA-256, SHA-1, or MD5 hash."
            )

    # Decision tree for the arguments
    # Check if the IP address is provided with the malware file/hash or domain
    if ip_address and (malware_file or malware_hash or domain):
        raise ValueError(
            "Please provide only one of --ip, --malware_file, --malware_hash, or --domain."
        )
    # If only the IP address is provided, perform the IP lookups
    elif ip_address and not (malware_file or malware_hash or domain):
        success_vt = vti.vt_ip_lookup(input_ip=ip_address)
        success_ii = ii.ii_ip_lookup(input_ip=ip_address)
        success_ai = ai.ai_ip_lookup(input_ip=ip_address)

        # If the lookups are successful, proceed to checks and save results in dictionaries
        # Otherwise, leave dictionaries empty to indicate failure
        if success_vt:
            vt_ip_osint = vti.vt_check_ip()
        else:
            vt_ip_osint = {}
        if success_ii:
            ii_ip_osint = ii.ii_check_ip()
        else:
            ii_ip_osint = {}
        if success_ai:
            ai_ip_osint = ai.ai_check_ip()
        else:
            ai_ip_osint = {}

        # Pass the dictionaries to the format_comment function
        comment = format_comment(
            vt_ip_osint=vt_ip_osint, ii_ip_osint=ii_ip_osint, ai_ip_osint=ai_ip_osint
        )
        print(comment)
    # If the malware file or hash is provided, perform the VirusTotal file lookup
    elif malware_file or malware_hash:
        # Convert the malware file to a SHA-256 hash first if malware_file is provided
        if malware_file and not malware_hash:
            malware_hash = hash_file(malware_file, "sha256")
        # Perform the VirusTotal file lookup
        success = vtf.vt_file_lookup(input_hash=malware_hash)
        if success:
            vt_file_osint = vtf.vt_check_file()
            comment = format_comment(vt_file_osint=vt_file_osint)
            print(comment)
        else:
            print(
                "Error looking up the file on VirusTotal. The file might not have been uploaded to VirusTotal yet."
            )
    # If the domain is provided, perform the VirusTotal domain lookup
    elif domain:
        success = vtd.vt_domain_lookup(input_domain=domain)
        if success:
            vt_domain_osint = vtd.vt_check_domain()
            comment = format_comment(vt_domain_osint=vt_domain_osint)
            print(comment)
        else:
            print("Error with the VirusTotal API call.")
    # If no or invalid arguments are provided, print an error
    else:
        raise ValueError(
            "Please provide one of --ip, --malware_file, --malware_hash, or --domain."
        )


if __name__ == "__main__":
    main()
