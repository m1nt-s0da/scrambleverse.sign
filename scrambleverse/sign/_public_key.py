from typing import TypedDict, IO
import json
from nacl.signing import VerifyKey as NaClVerifyKey
from nacl.exceptions import BadSignatureError
import base64
import hashlib
from datetime import datetime
from ._signer_info import SignerInfo

__all__ = ["PublicKey", "PublicKeyDict", "PublicKeyInfo"]


class PublicKeyInfo[T: SignerInfo = SignerInfo](TypedDict):
    date: str
    public_key: str
    signer_info: T


class PublicKeyDict(TypedDict):
    public_key_info: str
    signature: str


class PublicKey[T: SignerInfo = SignerInfo]:
    def __init__(self, public_key_info: str, signature: bytes):
        self.__public_key_info = public_key_info
        self.__signature = signature

    def to_dict(self) -> PublicKeyDict:
        return {
            "public_key_info": self.__public_key_info,
            "signature": self._signature_b64,
        }

    @property
    def _signature_b64(self) -> str:
        return base64.b64encode(self.__signature).decode("ascii")

    @property
    def _public_key_info(self) -> PublicKeyInfo[T]:
        return json.loads(self.__public_key_info)

    @property
    def signer_info(self) -> T:
        return self._public_key_info["signer_info"]

    @property
    def verify_key(self) -> NaClVerifyKey:
        return NaClVerifyKey(base64.b64decode(self._public_key_info["public_key"]))

    @property
    def date(self) -> datetime:
        return datetime.fromisoformat(self._public_key_info["date"])

    def verify_self(self):
        if not self.verify_digest(
            hashlib.sha256(self.__public_key_info.encode("ascii")).digest(),
            self.__signature,
        ):
            raise ValueError("Public key signature is invalid")

    def verify_digest(self, digest: bytes, signature: bytes) -> bool:
        try:
            self.verify_key.verify(digest, signature)
        except BadSignatureError:
            return False
        except Exception:
            raise
        else:
            return True

    @classmethod
    def parse(cls, data: PublicKeyDict):
        assert isinstance(data, dict)
        assert isinstance(data.get("public_key_info"), str)
        assert isinstance(data.get("signature"), str)

        key = cls(
            public_key_info=data["public_key_info"],
            signature=base64.b64decode(data["signature"]),
        )
        key.verify_self()
        return key

    @classmethod
    def load(cls, f: IO[str]):
        return cls.parse(json.load(f))

    @classmethod
    def from_file(cls, path: str):
        with open(path, "r", encoding="utf-8") as f:
            return cls.load(f)
