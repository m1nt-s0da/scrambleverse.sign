from argparse import ArgumentParser, FileType
from ._parser import subcommand
from typing import Protocol, TextIO
import sys
import json
from scrambleverse.sign import PrivateKey, Signatures
from hashlib import sha256

__all__ = []


class SignFileArgs(Protocol):
    input_files: list[str]
    key: TextIO
    output: TextIO


@subcommand("sign-file", help="Sign a file")
def sign_file(parser: ArgumentParser):
    parser.add_argument(
        "input_files",
        nargs="+",
        type=str,
        help="Path to the file to sign",
    )
    parser.add_argument(
        "-k",
        "--keyfile",
        type=FileType("r", encoding="utf-8"),
        required=True,
        help="Path to a file containing the private signing key",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=FileType("w", encoding="utf-8"),
        default=sys.stdout,
        help="Path to the output file (default: stdout)",
    )

    def handle(args: SignFileArgs):
        private_key = PrivateKey.load_and_decrypt_sync(args.key)
        signification = Signatures(private_key.generate_public_key())

        for file in args.input_files:
            hash = sha256()
            with open(file, "rb") as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    hash.update(chunk)

            signature = private_key.sign_digest(hash.digest())
            signification.add_signature(hash, signature)

        json.dump(signification.to_dict(), args.output, indent=2)

    return handle


if __name__ == "__main__":
    sign_file()
