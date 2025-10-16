import base64
from typing import TypedDict, Union, Callable, Awaitable, IO
from nacl import pwhash, secret, utils
from nacl.signing import SigningKey as NaClSigningKey
from nacl.encoding import Base64Encoder
from abc import ABC, abstractmethod
import json
import hashlib
from datetime import datetime, timezone
from ._public_key import PublicKey
from ._signer_info import SignerInfo

__all__ = ["PrivateKey", "EncryptedPrivateKey", "PrivateKeyDict"]


class PrivateKeyDict[T: SignerInfo = SignerInfo](TypedDict):
    signer_info: T
    private_key: str


async def default_passphrase_callback() -> str:
    from getpass import getpass

    return getpass("Enter passphrase to decrypt the signing key: ")


def default_passphrase_callback_sync() -> str:
    from getpass import getpass

    return getpass("Enter passphrase to decrypt the signing key: ")


class PrivateKeyBase[T: SignerInfo = SignerInfo](ABC):
    def __init__(self, signer_info: T):
        super().__init__()

        self.__signer_info = signer_info

    def to_dict(self) -> PrivateKeyDict[T]:
        return {
            "signer_info": self._signer_info,
            "private_key": self._ascii_encoded_key,
        }

    @property
    def _signer_info(self) -> T:
        return self.__signer_info

    @property
    @abstractmethod
    def _ascii_encoded_key(self) -> str: ...

    @classmethod
    def load(cls, file: IO):
        return cls.parse(json.load(file))

    @classmethod
    async def load_and_decrypt(
        cls,
        file: IO,
        passphrase_callback: Callable[[], Awaitable[str]] = default_passphrase_callback,
    ):
        data = json.load(file)
        return await cls.parse_and_decrypt(data, passphrase_callback)

    @classmethod
    def load_and_decrypt_sync(
        cls,
        file: IO,
        passphrase_callback: Callable[[], str] = default_passphrase_callback_sync,
    ):
        data = json.load(file)
        return cls.parse_and_decrypt_sync(data, passphrase_callback)

    @classmethod
    def from_file(cls, path: str):
        with open(path, "r", encoding="utf-8") as f:
            return cls.load(f)

    @classmethod
    async def from_file_and_decrypt(
        cls,
        path: str,
        passphrase_callback: Callable[[], Awaitable[str]] = default_passphrase_callback,
    ):
        with open(path, "r", encoding="utf-8") as f:
            return await cls.load_and_decrypt(f, passphrase_callback)

    @classmethod
    def from_file_and_decrypt_sync(
        cls,
        path: str,
        passphrase_callback: Callable[[], str] = default_passphrase_callback_sync,
    ):
        with open(path, "r", encoding="utf-8") as f:
            return cls.load_and_decrypt_sync(f, passphrase_callback)

    @staticmethod
    def parse(
        data: PrivateKeyDict[T],
    ) -> Union["PrivateKey[T]", "EncryptedPrivateKey[T]"]:
        assert isinstance(data, dict)
        assert isinstance(data.get("signer_info"), dict)
        assert isinstance(data["signer_info"].get("name"), str)
        assert isinstance(data.get("private_key"), str)

        signer_info = data["signer_info"]
        key = data["private_key"]

        parts = key.split(":")
        assert len(parts) in (1, 2), "Invalid private key format"
        if len(parts) == 1:
            decoded_key = base64.b64decode(parts[0])
            return PrivateKey(signer_info, decoded_key)
        else:
            salt = base64.b64decode(parts[0])
            encrypted_key = base64.b64decode(parts[1])
            return EncryptedPrivateKey(signer_info, salt, encrypted_key)

    @staticmethod
    async def parse_and_decrypt(
        data: PrivateKeyDict[T],
        passphrase_callback: Callable[[], Awaitable[str]] = default_passphrase_callback,
    ) -> "PrivateKey[T]":
        key = PrivateKeyBase[T].parse(data)
        if isinstance(key, EncryptedPrivateKey):
            passphrase = await passphrase_callback()
            return key.decrypt(passphrase)
        return key

    @staticmethod
    def parse_and_decrypt_sync(
        data: PrivateKeyDict[T],
        passphrase_callback: Callable[[], str] = default_passphrase_callback_sync,
    ) -> "PrivateKey[T]":
        key = PrivateKeyBase[T].parse(data)
        if isinstance(key, EncryptedPrivateKey):
            passphrase = passphrase_callback()
            return key.decrypt(passphrase)
        return key


class EncryptedPrivateKey[T: SignerInfo = SignerInfo](PrivateKeyBase[T]):
    def __init__(self, signer_info: T, salt: bytes, encrypted_key: bytes):
        super().__init__(signer_info)

        self.__salt = salt
        self.__encrypted_key = encrypted_key

    @property
    def salt(self) -> bytes:
        return self.__salt

    @property
    def encrypted_key(self) -> bytes:
        return self.__encrypted_key

    def decrypt(self, passphrase: str) -> "PrivateKey[T]":
        key = pwhash.argon2i.kdf(
            secret.SecretBox.KEY_SIZE,
            passphrase.encode("utf-8"),
            self.__salt,
            opslimit=pwhash.argon2i.OPSLIMIT_MODERATE,
            memlimit=pwhash.argon2i.MEMLIMIT_MODERATE,
        )
        box = secret.SecretBox(key)
        decrypted = box.decrypt(self.__encrypted_key)
        return PrivateKey(self._signer_info, decrypted)

    @property
    def _ascii_encoded_key(self) -> str:
        return (
            base64.b64encode(self.__salt)
            + b":"
            + base64.b64encode(self.__encrypted_key)
        ).decode("ascii")


class PrivateKey[T: SignerInfo = SignerInfo](PrivateKeyBase[T]):
    def __init__(self, signer_info: T, key: NaClSigningKey | bytes):
        super().__init__(signer_info)

        self.__key = key if isinstance(key, NaClSigningKey) else NaClSigningKey(key)

    @property
    def _nacl_signing_key(self) -> NaClSigningKey:
        return self.__key

    @property
    def _ascii_encoded_key(self) -> str:
        return base64.b64encode(self.__key.encode()).decode("ascii")

    @classmethod
    def generate(cls, signer_info: T) -> "PrivateKey[T]":
        assert isinstance(signer_info, dict)
        assert isinstance(signer_info.get("name"), str)

        return cls(signer_info, NaClSigningKey.generate())

    def encrypt(self, passphrase: str) -> EncryptedPrivateKey[T]:
        salt = utils.random(pwhash.argon2i.SALTBYTES)
        key = pwhash.argon2i.kdf(
            secret.SecretBox.KEY_SIZE,
            passphrase.encode("utf-8"),
            salt,
            opslimit=pwhash.argon2i.OPSLIMIT_MODERATE,
            memlimit=pwhash.argon2i.MEMLIMIT_MODERATE,
        )
        box = secret.SecretBox(key)
        encrypted = box.encrypt(self.__key.encode())
        return EncryptedPrivateKey(self._signer_info, salt, encrypted)

    def generate_public_key(self) -> PublicKey[T]:
        public_key_info = json.dumps(
            {
                "date": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "public_key": self.__key.verify_key.encode(
                    encoder=Base64Encoder
                ).decode("ascii"),
                "signer_info": self._signer_info,
            },
            ensure_ascii=True,
            separators=(",", ":"),
        )
        public_key_info_sha256 = hashlib.sha256(
            public_key_info.encode("ascii")
        ).digest()

        return PublicKey(
            public_key_info=public_key_info,
            signature=self.sign_digest(public_key_info_sha256),
        )

    def sign_digest(self, digest: bytes) -> bytes:
        return self.__key.sign(digest).signature
