from argparse import ArgumentParser, FileType
from ._parser import subcommand
from typing import Protocol, TextIO
import sys
from scrambleverse.sign import PublicKey

__all__ = []


class VerifyPublicKeyArgs(Protocol):
    public_key_file: TextIO


@subcommand("verify-public-key", help="Verify the integrity of a public signing key")
def verify_public_key(parser: ArgumentParser):
    parser.add_argument(
        "public_key_file",
        type=FileType("r", encoding="utf-8"),
        help="Path to a file containing the public signing key (default: stdin)",
    )

    def handler(args: VerifyPublicKeyArgs):
        public_key = PublicKey.load(args.public_key_file)
        try:
            public_key.verify_self()
        except:
            print("Public key is NOT valid!", file=sys.stderr)
        else:
            print("Public key is valid.", file=sys.stderr)

    return handler


if __name__ == "__main__":
    verify_public_key()
