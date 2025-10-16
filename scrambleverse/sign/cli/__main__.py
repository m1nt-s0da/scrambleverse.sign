from ._parser import parser

from . import (
    generate_private_key,
    generate_public_key,
    verify_public_key,
    sign_file,
    verify_file,
)


def main():
    parser()


if __name__ == "__main__":
    main()
