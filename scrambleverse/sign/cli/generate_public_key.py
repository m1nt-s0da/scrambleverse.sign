from argparse import ArgumentParser, FileType
from ._parser import subcommand
from typing import Protocol, TextIO
import sys
import json
from scrambleverse.sign import PrivateKey

__all__ = []


class ReadVerifyKeyArgs(Protocol):
    private_key_file: TextIO
    output: TextIO


@subcommand(
    "generate-public-key", help="Generate a public key from a private signing key"
)
def generate_public_key(parser: ArgumentParser):
    parser.add_argument(
        "private_key_file",
        type=FileType("r", encoding="utf-8"),
        help="Path to a file containing the private signing key (default: stdin)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=FileType("w", encoding="utf-8"),
        default=sys.stdout,
        help="Path to output the public key (default: stdout)",
    )

    def handler(args: ReadVerifyKeyArgs):
        signing_key = PrivateKey.load_and_decrypt_sync(args.private_key_file)
        public_key = signing_key.generate_public_key()
        json.dump(public_key.to_dict(), args.output, indent=2)

    return handler


if __name__ == "__main__":
    generate_public_key()
