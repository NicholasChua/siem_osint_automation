import argparse
import datetime
import ipaddress
import os
import hashlib
import json


def retrieve_secrets(*argv: str) -> dict[str, str] | str:
    """Retrieve secrets from a JSON file and return them as a dictionary.

    Args:
        secrets_file: The path to the JSON file containing the secrets.
        *argv: The list of secrets to retrieve from the JSON file.

    Returns:
        dict[str, str] | str: A dictionary containing the secrets or a string containing a secret
    """
    # Initialize the secrets dictionary
    secrets = {}

    # Get the path to the secrets file
    secrets_file = os.path.join(os.path.dirname(__file__), "..", "secrets.json")

    # Open the secrets file and load the secrets
    with open(secrets_file) as f:
        all_secrets = json.load(f)
        # Retrieve the specified secrets and add them to the secrets dictionary
        for arg in argv:
            secrets[arg] = all_secrets[arg]

    # If only one secret was requested, return it as a string
    if len(secrets) == 1:
        return secrets[arg]
    # Otherwise, return the secrets dictionary
    else:
        return secrets


def hash_file(file_path: str, algorithm: str) -> str:
    """Hash a file using a choice of MD5, SHA-1, or SHA-256 algorithm.

    Args:
        file_path: The path to the file to hash.
        algorithm: The hashing algorithm to use. Valid options are md5, sha1, or sha256.

    Returns:
        str: The hash of the file in the chosen algorithm.
    """
    # Initialize the hashing object
    if algorithm == "md5":
        hasher = hashlib.md5()
    elif algorithm == "sha1":
        hasher = hashlib.sha1()
    elif algorithm == "sha256":
        hasher = hashlib.sha256()
    else:
        raise ValueError(
            "Invalid hashing algorithm. Please choose md5, sha1, or sha256."
        )

    # Open the file and read it in chunks
    with open(file_path, "rb") as file:
        while chunk := file.read(4096):
            hasher.update(chunk)

    # Return the hash of the file
    return hasher.hexdigest()


def unix_timestamp_to_iso(timestamp: int, timezone: int = 0) -> str:
    """Convert a Unix timestamp to an ISO 8601 formatted string with timezone adjustment.

    Args:
        timestamp: The Unix timestamp to convert.
        timezone: The timezone offset in hours. Default is 0.

    Returns:
        str: The ISO 8601 formatted string.

    Exceptions:
        ValueError: If the timezone offset is not between -12 and 14.
        ValueError: If the Unix timestamp is negative.
    """
    # Validate the timezone offset
    if timezone < -12 or timezone > 14:
        raise ValueError("Invalid timezone offset. Please provide a value between -12 and 14.")
    
    # Validate the Unix timestamp
    if timestamp < 0:
        raise ValueError("Invalid Unix timestamp. Please provide a positive integer.")

    # Convert Unix timestamp to datetime object
    dt = datetime.datetime.fromtimestamp(timestamp)

    # Adjust for the timezone offset
    offset = datetime.timedelta(hours=timezone)

    # Convert datetime object to ISO 8601 string with timezone info
    formatted_dt = dt.replace(tzinfo=datetime.timezone(offset)).isoformat()
    return formatted_dt


def calculate_iso_time(
    days_before: int = 0, hours_before: int = 0, minutes_before: int = 0, timestamp_format: int = 0, timezone: int = 0
) -> dict[str, str]:
    """Return the current time in ISO 8601 format minus the specified number of days, hours, and minutes.
    The returned ISO8601 is in the format "YYYY-MM-DDThh:mm:ssZ".

    Args:
        days_before: The number of days to subtract from the current time
        hours_before: The number of hours to subtract from the current time
        minutes_before: The number of minutes to subtract from the current time
        timestamp_format: The format of the timestamp to return. Options are 0 for "YYYY-MM-DDThh:mm:ssZ" and 1 for "YYYY-MM-DD hh:mm:ss+hh:mm". Default is 0.
        timezone: The timezone offset in hours. Default is 0. Only used if timestamp_format is 1.

    Returns:
        dict: A dictionary containing the current time and the time minus the specified days, hours, and minutes. Both times are strings in ISO 8601 format.
    """
    # Get the current time
    current_time = datetime.datetime.now(datetime.UTC)

    # Format the current time based on timestamp_format
    if timestamp_format == 0:
        formatted_current_time = current_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    elif timestamp_format == 1:
        # Adjust for the timezone offset
        offset = datetime.timedelta(hours=timezone)
        current_time = current_time + offset
        formatted_current_time = current_time.replace(tzinfo=datetime.timezone(offset)).isoformat()
    else:
        raise ValueError("Invalid timestamp format. Please choose 0 or 1.")

    # Subtract the specified days, hours, and minutes from the current time
    time_delta = datetime.timedelta(
        days=days_before, hours=hours_before, minutes=minutes_before
    )
    subtracted_time = current_time - time_delta

    # Format the subtracted time based on timestamp_format
    if timestamp_format == 0:
        formatted_subtracted_time = subtracted_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    elif timestamp_format == 1:
        # Adjust for the timezone offset
        formatted_subtracted_time = subtracted_time.replace(tzinfo=datetime.timezone(offset)).isoformat()

    # Return the current time and the time minus the specified days, hours, and minutes
    return {
        "current_time": formatted_current_time,
        "before_time": formatted_subtracted_time,
    }


def ip_input_validation(ip: str) -> bool:
    """Validate the input IP address using the ipaddress module.

    Args:
        ip: The IP address to validate.

    Returns:
        bool: True if the IP address is valid, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
    # If an exception happens the validation fails anyway so return False
    except Exception:
        return False


def hash_input_validation(hash: str) -> bool:
    """Validate the input hash is a valid SHA-256, SHA-1, or MD5 hash.

    Args:
        hash: The hash to validate.

    Returns:
        bool: True if the hash is valid, False otherwise
    """
    if len(hash) == 64:
        # Valid SHA-256 hash
        return True
    elif len(hash) == 40:
        # Valid SHA-1 hash
        return True
    elif len(hash) == 32:
        # Valid MD5 hash
        return True
    else:
        return False


def add_argparser_arguments(
    ip: bool = False, response_file: bool = False, response_dir: bool = False, malware_file: bool = False, malware_hash: bool = False, domain: bool = False
) -> argparse.ArgumentParser:
    """Add arguments to the ArgumentParser object for the script to take in user inputs.
    This function takes in boolean arguments to determine which arguments should be provided.

    Args:
        ip: A boolean indicating whether the IP address argument should be added. Default is False.
        response_file: A boolean indicating whether the response filename argument should be added. Default is False.
        response_dir: A boolean indicating whether the directory argument should be added. Default is False.
        malware_file: A boolean indicating whether the malware filename argument should be added. Default is False.
        malware_hash: A boolean indicating whether the malware hash argument should be added. Default is False.
        domain: A boolean indicating whether the domain argument should be added. Default is False.

    Returns:
        ArgumentParser: The ArgumentParser object with the added arguments.
    """
    # Initialize the ArgumentParser object
    parser = argparse.ArgumentParser()

    # Add arguments to the ArgumentParser object based on the provided booleans
    if ip:
        parser.add_argument(
            "--ip",
            "-i",
            type=str,
            help="The IP address to look up.",
            required=False,
        )

    if response_file:
        parser.add_argument(
            "--response_file",
            "-rf",
            type=str,
            help="The filename of the JSON response from the IP lookup.",
            required=False,
        )

    if response_dir:
        parser.add_argument(
            "--response_dir",
            "-rd",
            type=str,
            help="The directory of the JSON response from the IP lookup. Must be used with --response_file",
            required=False,
        )

    if malware_file:
        parser.add_argument(
            "--malware_file",
            "-mf",
            type=str,
            help="The malware file to look up.",
            required=False,
        )

    if malware_hash:
        parser.add_argument(
            "--malware_hash",
            "-mh",
            type=str,
            help="The hash of the malware file to look up.",
            required=False,
        )

    if domain:
        parser.add_argument(
            "--domain",
            "-d",
            type=str,
            help="The domain to look up.",
            required=False,
        )

    args = parser.parse_args()
    return args
