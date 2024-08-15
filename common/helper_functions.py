import argparse
import json
import os
import datetime
import hashlib


def retrieve_secrets(*argv: str) -> dict | str:
    """Retrieve secrets from a JSON file and return them as a dictionary.

    Args:
        secrets_file: The path to the JSON file containing the secrets.
        *argv: The list of secrets to retrieve from the JSON file.

    Returns:
        dict | str: A dictionary containing the secrets or a string containing a secret
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


def unix_timestamp_to_iso(timestamp: int) -> str:
    """Convert a Unix timestamp to an ISO 8601 formatted string.

    Args:
        timestamp: The Unix timestamp to convert.

    Returns:
        str: The ISO 8601 formatted string.
    """
    # Convert Unix timestamp to datetime object
    dt = datetime.datetime.fromtimestamp(timestamp)

    # Convert datetime object to ISO 8601 string
    return dt.isoformat()


def add_argparser_arguments(
    ip: bool = False, response_file: bool = False, response_dir: bool = False, malware_file: bool = False, malware_hash: bool = False, domain: bool = False) -> argparse.ArgumentParser:
    """Add arguments to the ArgumentParser object for the script to take in user inputs.
    This function takes in boolean arguments to determine which arguments should be provided.

    Args:
        ip: A boolean indicating whether the IP address argument should be added.
        response_file: A boolean indicating whether the filename argument should be added.
        response_dir: A boolean indicating whether the directory argument should be added.
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
