import argparse
import datetime
import ipaddress
import vt_ip_osint as vt
import ii_ip_osint as ii
import ai_ip_osint as ai


def format_comment(vt_ip_osint: dict = {}, ii_ip_osint: dict = {}, ai_ip_osint: dict = {}) -> str:
    """Function to format the IP OSINT details from VirusTotal, ipinfo.io and AbuseIPDB into a comment.

    Args:
    vt_ip_osint: A dictionary containing the IP OSINT details from vt_check_ip(). Default is an empty dictionary.
    ii_ip_osint: A dictionary containing the IP OSINT details from ii_check_ip(). Default is an empty dictionary.
    ai_ip_osint: A dictionary containing the IP OSINT details from ai_check_ip(). Default is an empty dictionary.

    Returns:
    str: A formatted comment with the IP OSINT details. Each detail is on a new line with a '- ' prefix and ends with a newline character.
    """
    # Initialize the comment list
    comment = ["SOAP_auto_analysis:"]

    # Get the current timestamp in ISO 8601 format and print it
    timestamp = datetime.datetime.now(
        datetime.timezone(datetime.timedelta(hours=8))
    ).isoformat()

    # Initialize the comment list with the timestamp
    comment += [f"- Analyzed at {timestamp}."]

    # Check for presence of filled vt_ip_osint, ii_ip_osint, and ai_ip_osint dictionaries
    if vt_ip_osint == {} and ii_ip_osint == {} and ai_ip_osint == {}:
        raise Exception("VirusTotal, ipinfo IP OSINT, and AbuseIPDB dictionaries are empty.")

    if vt_ip_osint:
        try:
            comment += [f"- VirusTotal Link: https://www.virustotal.com/gui/ip-address/{vt_ip_osint['ip']}"]

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
            # TODO: Handle the exception
            print("Error in vt_ip_osint.")
            exit(1)

    if ii_ip_osint:
        try:
            comment += [f"- ipinfo Link: https://ipinfo.io/{ii_ip_osint['ip']}"]
            comment += [f"- IP Geolocation is in country {ii_ip_osint['country']}, region {ii_ip_osint['region']}, city {ii_ip_osint['city']}."]
            comment += [f"- IP belongs to: {ii_ip_osint['organization']}"]
        except KeyError:
            print("Missing key in ii_ip_osint. Assuming it is empty.")
            pass
        except:
            # TODO: Handle the exception
            print("Error in ii_ip_osint.")
            exit(1)

    if ai_ip_osint:
        try:
            comment += [f"- AbuseIPDB Link: https://www.abuseipdb.com/check/{ai_ip_osint['ip']}"]
            comment += [f"- Abuse Confidence Score: {ai_ip_osint['abuseConfidenceScore']}"]
            
            # Print an appropriate message based on the isTor value
            if ai_ip_osint["isTor"]:
                comment += ["- IP is a Tor exit node."]
            else:
                comment += ["- IP is not a Tor exit node."]

        except KeyError:
            print("Missing key in ai_ip_osint. Assuming it is empty.")
            pass
        except:
            # TODO: Handle the exception
            print("Error in ii_ip_osint.")
            exit(1)

    # Convert the comment list to a string
    commentStr = "\n".join(comment)

    return commentStr


def main():
    # Set up the argument parser
    parser = argparse.ArgumentParser()

    # Add arguments
    parser.add_argument(
        "--ip",
        "-i",
        type=str,
        help="The IP address to look up.",
        required=True,
    )

    # Parse arguments
    args = parser.parse_args()
    ip_address = args.ip

    # Perform input validation of IP address using built-in ipaddress module
    if ip_address:
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            print("Invalid IP address. Please provide a valid IP address.")
            exit(1)

    # Perform the IP lookups
    success_vt = vt.vt_ip_lookup(input_ip=ip_address)
    success_ii = ii.ii_ip_lookup(input_ip=ip_address)
    success_ai = ai.ai_ip_lookup(input_ip=ip_address)

    # If the lookups are successful, proceed to checks and save results in dictionaries
    # Otherwise, leave dictionaries empty to indicate failure
    if success_vt:
        vt_ip_osint = vt.vt_check_ip()
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
    comment = format_comment(vt_ip_osint=vt_ip_osint, ii_ip_osint=ii_ip_osint, ai_ip_osint=ai_ip_osint)
    print(comment)


if __name__ == "__main__":
    main()
