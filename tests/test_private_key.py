import pytest
import base64
import json
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock
from io import StringIO

from scrambleverse.sign import PrivateKey, EncryptedPrivateKey, SignerInfo


class TestSignerInfo:
    def test_signer_info_creation(self):
        """Test that SignerInfo can be created with valid data."""
        signer_info: SignerInfo = {"name": "Test Signer"}
        assert signer_info["name"] == "Test Signer"

    def test_signer_info_type_validation(self):
        """Test that SignerInfo requires proper typing."""
        # This should be valid
        signer_info: SignerInfo = {"name": "Valid Name"}
        assert isinstance(signer_info["name"], str)


class TestPrivateKey:
    def setup_method(self):
        """Set up test fixtures."""
        self.test_signer_info: SignerInfo = {"name": "Test User"}

    def test_private_key_generation(self):
        """Test generation of a new private key."""
        private_key = PrivateKey.generate(self.test_signer_info)

        assert private_key._signer_info == self.test_signer_info
        assert hasattr(private_key, "_nacl_signing_key")
        assert private_key._ascii_encoded_key is not None

    def test_private_key_to_dict(self):
        """Test conversion of private key to dictionary."""
        private_key = PrivateKey.generate(self.test_signer_info)
        key_dict = private_key.to_dict()

        assert "signer_info" in key_dict
        assert "private_key" in key_dict
        assert key_dict["signer_info"] == self.test_signer_info
        assert isinstance(key_dict["private_key"], str)

    def test_private_key_from_dict_parsing(self):
        """Test parsing private key from dictionary."""
        # Generate a test key
        original_key = PrivateKey.generate(self.test_signer_info)
        key_dict = original_key.to_dict()

        # Parse it back
        parsed_key = PrivateKey.parse(key_dict)

        assert isinstance(parsed_key, PrivateKey)
        assert parsed_key._signer_info == self.test_signer_info

    def test_private_key_encryption_and_decryption(self):
        """Test encryption and decryption of private key."""
        private_key = PrivateKey.generate(self.test_signer_info)
        passphrase = "test_passphrase_123"

        # Encrypt the key
        encrypted_key = private_key.encrypt(passphrase)
        assert isinstance(encrypted_key, EncryptedPrivateKey)
        assert encrypted_key.salt is not None
        assert encrypted_key.encrypted_key is not None

        # Decrypt the key
        decrypted_key = encrypted_key.decrypt(passphrase)
        assert isinstance(decrypted_key, PrivateKey)
        assert decrypted_key._signer_info == self.test_signer_info

    def test_private_key_sign_digest(self):
        """Test signing a digest with private key."""
        private_key = PrivateKey.generate(self.test_signer_info)
        test_digest = b"test message digest"

        signature = private_key.sign_digest(test_digest)
        assert isinstance(signature, bytes)
        assert len(signature) > 0

    def test_private_key_generate_public_key(self):
        """Test generating public key from private key."""
        private_key = PrivateKey.generate(self.test_signer_info)
        public_key = private_key.generate_public_key()

        assert public_key.signer_info == self.test_signer_info
        assert isinstance(public_key.date, datetime)

        # Test that the public key can verify its own signature
        public_key.verify_self()  # Should not raise exception

    def test_encrypted_private_key_ascii_encoding(self):
        """Test ASCII encoding of encrypted private key."""
        private_key = PrivateKey.generate(self.test_signer_info)
        encrypted_key = private_key.encrypt("test_passphrase")

        ascii_encoded = encrypted_key._ascii_encoded_key
        assert ":" in ascii_encoded  # Should contain salt:encrypted_key format

        parts = ascii_encoded.split(":")
        assert len(parts) == 2

        # Should be valid base64
        try:
            base64.b64decode(parts[0])  # salt
            base64.b64decode(parts[1])  # encrypted key
        except Exception:
            pytest.fail("ASCII encoded key parts should be valid base64")

    def test_parse_encrypted_private_key(self):
        """Test parsing encrypted private key from dictionary."""
        private_key = PrivateKey.generate(self.test_signer_info)
        encrypted_key = private_key.encrypt("test_passphrase")
        key_dict = encrypted_key.to_dict()

        parsed_key = PrivateKey.parse(key_dict)
        assert isinstance(parsed_key, EncryptedPrivateKey)
        assert parsed_key._signer_info == self.test_signer_info

    @patch("getpass.getpass")
    def test_load_and_decrypt_sync(self, mock_getpass):
        """Test synchronous loading and decryption from file."""
        mock_getpass.return_value = "test_passphrase"

        # Create test data
        private_key = PrivateKey.generate(self.test_signer_info)
        encrypted_key = private_key.encrypt("test_passphrase")
        key_dict = encrypted_key.to_dict()

        # Create mock file
        mock_file = StringIO(json.dumps(key_dict))

        # Test loading and decryption
        loaded_key = PrivateKey.load_and_decrypt_sync(mock_file)
        assert isinstance(loaded_key, PrivateKey)
        assert loaded_key._signer_info == self.test_signer_info

    @pytest.mark.asyncio
    @patch("getpass.getpass")
    async def test_load_and_decrypt_async(self, mock_getpass):
        """Test asynchronous loading and decryption from file."""
        mock_getpass.return_value = "test_passphrase"

        # Create test data
        private_key = PrivateKey.generate(self.test_signer_info)
        encrypted_key = private_key.encrypt("test_passphrase")
        key_dict = encrypted_key.to_dict()

        # Create mock file
        mock_file = StringIO(json.dumps(key_dict))

        # Test async loading and decryption
        loaded_key = await PrivateKey.load_and_decrypt(mock_file)
        assert isinstance(loaded_key, PrivateKey)
        assert loaded_key._signer_info == self.test_signer_info

    def test_invalid_private_key_format(self):
        """Test error handling for invalid private key format."""
        invalid_data = {
            "signer_info": {"name": "Test"},
            "private_key": "invalid:format:too:many:parts",
        }

        with pytest.raises(AssertionError, match="Invalid private key format"):
            PrivateKey.parse(invalid_data)  # type: ignore

    def test_invalid_signer_info(self):
        """Test error handling for invalid signer info."""
        invalid_data = {
            "signer_info": {"name": 123},  # Should be string
            "private_key": "dGVzdA==",
        }

        with pytest.raises(AssertionError):
            PrivateKey.parse(invalid_data)  # type: ignore

    def test_missing_fields(self):
        """Test error handling for missing required fields."""
        # Missing signer_info
        with pytest.raises(AssertionError):
            PrivateKey.parse({"private_key": "dGVzdA=="})  # type: ignore

        # Missing private_key
        with pytest.raises(AssertionError):
            PrivateKey.parse({"signer_info": {"name": "Test"}})  # type: ignore

    def test_wrong_passphrase_decryption(self):
        """Test that wrong passphrase fails gracefully."""
        private_key = PrivateKey.generate(self.test_signer_info)
        encrypted_key = private_key.encrypt("correct_passphrase")

        # Attempt to decrypt with wrong passphrase should raise an exception
        with pytest.raises(Exception):  # NaCl will raise some form of exception
            encrypted_key.decrypt("wrong_passphrase")


class TestEncryptedPrivateKey:
    def setup_method(self):
        """Set up test fixtures."""
        self.test_signer_info: SignerInfo = {"name": "Test User"}

    def test_encrypted_key_properties(self):
        """Test that encrypted key has required properties."""
        private_key = PrivateKey.generate(self.test_signer_info)
        encrypted_key = private_key.encrypt("test_passphrase")

        assert hasattr(encrypted_key, "salt")
        assert hasattr(encrypted_key, "encrypted_key")
        assert isinstance(encrypted_key.salt, bytes)
        assert isinstance(encrypted_key.encrypted_key, bytes)
        assert len(encrypted_key.salt) > 0
        assert len(encrypted_key.encrypted_key) > 0

    def test_encrypted_key_roundtrip(self):
        """Test that encryption and decryption preserves the original key."""
        original_key = PrivateKey.generate(self.test_signer_info)
        passphrase = "test_passphrase_roundtrip"

        # Get original key material
        original_encoded = original_key._ascii_encoded_key

        # Encrypt and decrypt
        encrypted_key = original_key.encrypt(passphrase)
        decrypted_key = encrypted_key.decrypt(passphrase)

        # Compare key material
        assert decrypted_key._ascii_encoded_key == original_encoded

    def test_different_passphrases_different_encryption(self):
        """Test that different passphrases produce different encrypted results."""
        private_key = PrivateKey.generate(self.test_signer_info)

        encrypted1 = private_key.encrypt("passphrase1")
        encrypted2 = private_key.encrypt("passphrase2")

        # Different passphrases should produce different encrypted data
        assert encrypted1.encrypted_key != encrypted2.encrypted_key
        # But same salt length
        assert len(encrypted1.salt) == len(encrypted2.salt)
