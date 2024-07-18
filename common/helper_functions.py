import argparse
import json
import os


def retrieve_secrets(*argv: str) -> dict | str:
    """Retrieve secrets from a JSON file and return them as a dictionary.

    Args:
        secrets_file (str): The path to the JSON file containing the secrets.
        *argv (str): The list of secrets to retrieve from the JSON file.

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


def add_argparser_arguments(
    ip: bool, response_file: bool, response_dir: bool
) -> argparse.ArgumentParser:
    """Add arguments to the ArgumentParser object for the script to take in user inputs.
    This function takes in boolean arguments to determine which arguments should be provided.

    Args:
        ip: A boolean indicating whether the IP address argument should be added.
        response_file: A boolean indicating whether the filename argument should be added.
        response_dir: A boolean indicating whether the directory argument should be added.

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
            "-f",
            type=str,
            help="The filename of the JSON response from the IP lookup.",
            required=False,
        )

    if response_dir:
        parser.add_argument(
            "--response_dir",
            "-d",
            type=str,
            help="The directory of the JSON response from the IP lookup. Must be used with --response_file",
            required=False,
        )

    args = parser.parse_args()
    return args
