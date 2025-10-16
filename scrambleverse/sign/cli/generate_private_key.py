from argparse import ArgumentParser, FileType
from ._parser import subcommand
import sys
from typing import Protocol, TextIO
import json
from scrambleverse.sign import PrivateKey, SignerInfo
from getpass import getpass


class GenerateKeyArgs(Protocol):
    signer_info_file: TextIO
    output: TextIO


@subcommand("generate-private-key", help="Generate a new private signing key")
def generate_private_key(parser: ArgumentParser):
    parser.add_argument(
        "signer_info_file",
        type=FileType("r", encoding="utf-8"),
        help="Path to a JSON file containing signer information (default: stdin)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=FileType("w", encoding="utf-8"),
        default=sys.stdout,
        help="Path to output the generated key pair (default: stdout)",
    )

    def handler(args: GenerateKeyArgs):
        signer_info: SignerInfo = json.load(args.signer_info_file)

        signing_key = PrivateKey.generate(signer_info)

        passphrase = getpass("Enter passphrase to encrypt the signing key: ")
        if passphrase != "":
            if passphrase == getpass("Re-enter passphrase: "):
                signing_key = signing_key.encrypt(passphrase)
            else:
                print("Passphrases do not match. Aborted.", file=sys.stderr)
                return
        else:
            if (
                input(
                    "No passphrase entered. The signing key will be stored unencrypted. Continue? (y/N) "
                )
                .strip()
                .lower()
                != "y"
            ):
                print("Aborted.", file=sys.stderr)
                return

        json.dump(signing_key.to_dict(), args.output, indent=2)

    return handler


if __name__ == "__main__":
    generate_private_key()
