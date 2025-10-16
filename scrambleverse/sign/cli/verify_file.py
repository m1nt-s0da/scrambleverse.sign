from argparse import ArgumentParser, FileType
from ._parser import subcommand
from typing import Protocol, TextIO, TypedDict
import sys
from scrambleverse.sign import PublicKeyDict, Signatures
from hashlib import sha256

__all__ = []


class VerifyFileArgs(Protocol):
    input_files: list[str]
    signatures: TextIO


class SignatureEntry(TypedDict):
    sha256: str
    signature: str


class SignaturesFile(TypedDict):
    public_key: PublicKeyDict
    files: list[SignatureEntry]


@subcommand("verify-file", help="Verify a signed file")
def verify_file(parser: ArgumentParser):
    parser.add_argument(
        "input_files",
        nargs="+",
        type=str,
        help="Path to the file to verify",
    )
    parser.add_argument(
        "-s",
        "--signatures",
        type=FileType("r", encoding="utf-8"),
        required=True,
        help="Path to a file containing the signatures",
    )

    def handler(args: VerifyFileArgs):
        signatures = Signatures.load(args.signatures)
        invalid = 0

        for file in args.input_files:
            hash = sha256()
            with open(file, "rb") as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    hash.update(chunk)

            if signatures.verify(hash):
                print(f"{file}: Signature is valid", file=sys.stdout)
            else:
                print(f"{file}: Signature is INVALID", file=sys.stderr)
                invalid += 1
                continue

        if invalid > 0:
            sys.exit(1)

    return handler


if __name__ == "__main__":
    verify_file()
