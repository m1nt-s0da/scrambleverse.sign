from typing import TypedDict, TYPE_CHECKING, IO, Union
from functools import cache
import base64
import json
from ._public_key import PublicKeyDict, PublicKey
from ._signer_info import SignerInfo

if TYPE_CHECKING:
    from hashlib import _Hash

__all__ = ["Signatures", "SignaturesDict", "SignatureEntry"]


class SignatureEntry(TypedDict):
    sha256: str
    signature: str


class SignaturesDict(TypedDict):
    public_key: PublicKeyDict
    files: list[SignatureEntry]


class Signatures[T: SignerInfo = SignerInfo]:
    def __init__(self, public_key: PublicKey[T], files: list[SignatureEntry] = []):
        self.__public_key = public_key
        self.__files = files

    @property
    def public_key(self) -> PublicKey[T]:
        return self.__public_key

    @cache
    def _signature_map(self) -> dict[str, str]:
        return {entry["sha256"]: entry["signature"] for entry in self.__files}

    def add_signature(self, sha256: "_Hash", signature: bytes):
        self.__files.append(
            {
                "sha256": sha256.hexdigest(),
                "signature": base64.b64encode(signature).decode("ascii"),
            }
        )
        self._signature_map.cache_clear()

    def verify(self, sha256: Union["_Hash", str]) -> bool:
        if isinstance(sha256, str):
            hex_digest = sha256
        else:
            hex_digest = sha256.hexdigest()
            if hex_digest not in self._signature_map():
                return False
        signature = base64.b64decode(self._signature_map()[hex_digest])
        return self.__public_key.verify_digest(bytes.fromhex(hex_digest), signature)

    def to_dict(self) -> SignaturesDict:
        return {
            "public_key": self.__public_key.to_dict(),
            "files": self.__files,
        }

    @classmethod
    def parse(cls, data: SignaturesDict):
        return cls(PublicKey[T].parse(data["public_key"]), data["files"])

    @classmethod
    def load(cls, f: IO[str]):
        return cls.parse(json.load(f))

    @classmethod
    def from_file(cls, path: str):
        with open(path, "r", encoding="utf-8") as f:
            return cls.load(f)
