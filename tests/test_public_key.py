import pytest
import json
import base64
import hashlib
from datetime import datetime, timezone
from unittest.mock import MagicMock
from io import StringIO

from scrambleverse.sign import PublicKey, PrivateKey, SignerInfo
from nacl.exceptions import BadSignatureError


class TestPublicKey:
    def setup_method(self):
        """Set up test fixtures."""
        self.test_signer_info: SignerInfo = {"name": "Test User"}
        self.private_key = PrivateKey.generate(self.test_signer_info)
        self.public_key = self.private_key.generate_public_key()

    def test_public_key_creation_from_private_key(self):
        """Test that public key can be generated from private key."""
        assert self.public_key.signer_info == self.test_signer_info
        assert isinstance(self.public_key.date, datetime)

        # Verify the public key is self-signed
        self.public_key.verify_self()  # Should not raise exception

    def test_public_key_properties(self):
        """Test public key properties."""
        # Test signer_info property
        assert self.public_key.signer_info == self.test_signer_info

        # Test date property
        date = self.public_key.date
        assert isinstance(date, datetime)
        assert date.tzinfo is not None  # Should have timezone info

        # Test verify_key property
        verify_key = self.public_key.verify_key
        assert verify_key is not None

    def test_public_key_to_dict(self):
        """Test conversion of public key to dictionary."""
        key_dict = self.public_key.to_dict()

        assert "public_key_info" in key_dict
        assert "signature" in key_dict
        assert isinstance(key_dict["public_key_info"], str)
        assert isinstance(key_dict["signature"], str)

        # Verify signature is valid base64
        try:
            base64.b64decode(key_dict["signature"])
        except Exception:
            pytest.fail("Signature should be valid base64")

    def test_public_key_info_parsing(self):
        """Test parsing of public key info."""
        public_key_info = self.public_key._public_key_info

        assert "date" in public_key_info
        assert "public_key" in public_key_info
        assert "signer_info" in public_key_info

        assert isinstance(public_key_info["date"], str)
        assert isinstance(public_key_info["public_key"], str)
        assert public_key_info["signer_info"] == self.test_signer_info

    def test_public_key_roundtrip_serialization(self):
        """Test that public key can be serialized and deserialized."""
        # Serialize to dict
        key_dict = self.public_key.to_dict()

        # Deserialize back to PublicKey
        parsed_key = PublicKey.parse(key_dict)

        # Verify they're equivalent
        assert parsed_key.signer_info == self.public_key.signer_info
        assert parsed_key.to_dict() == key_dict

    def test_public_key_verify_digest(self):
        """Test verifying a digest with the public key."""
        test_message = b"test message for signing"
        digest = hashlib.sha256(test_message).digest()

        # Sign with private key
        signature = self.private_key.sign_digest(digest)

        # Verify with public key
        assert self.public_key.verify_digest(digest, signature) is True

        # Test with wrong digest
        wrong_digest = hashlib.sha256(b"different message").digest()
        assert self.public_key.verify_digest(wrong_digest, signature) is False

    def test_public_key_verify_self(self):
        """Test self-verification of public key."""
        # Valid public key should verify successfully
        self.public_key.verify_self()  # Should not raise exception

        # Create invalid public key by modifying signature (use proper 64-byte signature)
        key_dict = self.public_key.to_dict()
        invalid_signature = base64.b64encode(b"x" * 64).decode("ascii")  # 64 bytes

        invalid_public_key = PublicKey(
            public_key_info=key_dict["public_key_info"],
            signature=base64.b64decode(invalid_signature),
        )

        # Invalid public key should raise ValueError
        with pytest.raises(ValueError, match="Public key signature is invalid"):
            invalid_public_key.verify_self()

    def test_public_key_load_from_file(self):
        """Test loading public key from file-like object."""
        key_dict = self.public_key.to_dict()
        mock_file = StringIO(json.dumps(key_dict))

        loaded_key = PublicKey.load(mock_file)

        assert loaded_key.signer_info == self.public_key.signer_info
        assert loaded_key.to_dict() == key_dict

    def test_public_key_parse_validation(self):
        """Test validation during parsing."""
        valid_dict = self.public_key.to_dict()

        # Test successful parsing
        parsed_key = PublicKey.parse(valid_dict)
        assert parsed_key.signer_info == self.test_signer_info

    def test_public_key_parse_invalid_data(self):
        """Test error handling for invalid data during parsing."""
        # Missing public_key_info
        with pytest.raises(AssertionError):
            PublicKey.parse({"signature": "dGVzdA=="})  # type: ignore

        # Missing signature
        with pytest.raises(AssertionError):
            PublicKey.parse({"public_key_info": "test"})  # type: ignore

        # Wrong types
        with pytest.raises(AssertionError):
            PublicKey.parse(
                {
                    "public_key_info": 123,  # type: ignore
                    "signature": "dGVzdA==",
                }
            )

    def test_public_key_parse_invalid_signature(self):
        """Test error handling for invalid signature during parsing."""
        key_dict = self.public_key.to_dict()
        key_dict["signature"] = base64.b64encode(b"x" * 64).decode(
            "ascii"
        )  # Valid length but wrong signature

        with pytest.raises(ValueError, match="Public key signature is invalid"):
            PublicKey.parse(key_dict)

    def test_public_key_bad_signature_verification(self):
        """Test handling of bad signature exceptions."""
        # Create a digest and an invalid signature (but proper length)
        digest = hashlib.sha256(b"test message").digest()
        invalid_signature = b"x" * 64  # Proper length but invalid signature

        # This should return False, not raise BadSignatureError
        result = self.public_key.verify_digest(digest, invalid_signature)
        assert result is False

    def test_public_key_date_format(self):
        """Test that the date is properly formatted with timezone info."""
        date = self.public_key.date

        # Should be able to convert back to string and parse again
        date_str = date.isoformat(timespec="milliseconds")
        parsed_date = datetime.fromisoformat(date_str)

        assert parsed_date == date

    def test_multiple_public_keys_from_same_private_key(self):
        """Test that multiple public keys generated from same private key have different dates but same key material."""
        public_key1 = self.private_key.generate_public_key()

        # Wait a moment to ensure different timestamp
        import time

        time.sleep(0.001)

        public_key2 = self.private_key.generate_public_key()

        # Should have same signer info and key material but different dates
        assert public_key1.signer_info == public_key2.signer_info
        assert public_key1.verify_key.encode() == public_key2.verify_key.encode()

        # Dates should be different (though very close)
        assert public_key1.date != public_key2.date

    def test_public_key_signature_b64_property(self):
        """Test the base64 signature property."""
        signature_b64 = self.public_key._signature_b64

        assert isinstance(signature_b64, str)

        # Should be valid base64
        try:
            decoded = base64.b64decode(signature_b64)
            assert len(decoded) > 0
        except Exception:
            pytest.fail("_signature_b64 should be valid base64")

    def test_verify_key_property(self):
        """Test that verify_key property returns valid NaCl VerifyKey."""
        verify_key = self.public_key.verify_key

        # Should be able to use it for verification
        test_digest = hashlib.sha256(b"test").digest()
        signature = self.private_key.sign_digest(test_digest)

        # Should not raise exception for valid signature
        verify_key.verify(test_digest, signature)

        # Should raise BadSignatureError for invalid signature (proper length)
        with pytest.raises(BadSignatureError):
            verify_key.verify(test_digest, b"x" * 64)  # 64 bytes but invalid
