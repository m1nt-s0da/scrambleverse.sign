import pytest
import json
import hashlib
import base64
from io import StringIO
from unittest.mock import patch

from scrambleverse.sign import Signatures, PrivateKey, PublicKey, SignerInfo


class TestSignatures:
    def setup_method(self):
        """Set up test fixtures."""
        self.test_signer_info: SignerInfo = {"name": "Test User"}
        self.private_key = PrivateKey.generate(self.test_signer_info)
        self.public_key = self.private_key.generate_public_key()
        self.signatures = Signatures(self.public_key, [])  # Start with empty list

    def test_signatures_creation(self):
        """Test creating a Signatures object."""
        assert self.signatures.public_key == self.public_key

    def test_add_signature(self):
        """Test adding a signature to the collection."""
        test_data = b"test file content"
        hash_obj = hashlib.sha256(test_data)
        signature = self.private_key.sign_digest(hash_obj.digest())

        # Add signature
        self.signatures.add_signature(hash_obj, signature)

        # Verify it was added
        signatures_dict = self.signatures.to_dict()
        assert len(signatures_dict["files"]) == 1

        file_entry = signatures_dict["files"][0]
        assert file_entry["sha256"] == hash_obj.hexdigest()
        assert isinstance(file_entry["signature"], str)

        # Verify signature is valid base64
        try:
            decoded_sig = base64.b64decode(file_entry["signature"])
            assert decoded_sig == signature
        except Exception:
            pytest.fail("Signature should be valid base64")

    def test_verify_signature_with_hash_object(self):
        """Test verifying a signature using hash object."""
        test_data = b"test file content for verification"
        hash_obj = hashlib.sha256(test_data)
        signature = self.private_key.sign_digest(hash_obj.digest())

        # Add signature
        self.signatures.add_signature(hash_obj, signature)

        # Create new hash object with same data
        verify_hash = hashlib.sha256(test_data)

        # Verify signature
        assert self.signatures.verify(verify_hash) is True

    def test_verify_signature_with_hex_string(self):
        """Test verifying a signature using hex digest string."""
        test_data = b"test file content for hex verification"
        hash_obj = hashlib.sha256(test_data)
        signature = self.private_key.sign_digest(hash_obj.digest())

        # Add signature
        self.signatures.add_signature(hash_obj, signature)

        # Verify using hex string
        hex_digest = hash_obj.hexdigest()
        assert self.signatures.verify(hex_digest) is True

    def test_verify_nonexistent_signature(self):
        """Test verifying a signature that doesn't exist."""
        # Try to verify a hash that was never signed
        test_hash = hashlib.sha256(b"never signed content")
        assert self.signatures.verify(test_hash) is False

    def test_verify_invalid_signature(self):
        """Test verifying with invalid signature data."""
        test_data = b"test content"
        hash_obj = hashlib.sha256(test_data)

        # Create a signatures object with pre-populated invalid data
        # Use 64-byte signature but with wrong content
        invalid_files = [
            {
                "sha256": hash_obj.hexdigest(),
                "signature": base64.b64encode(b"x" * 64).decode(
                    "ascii"
                ),  # Wrong but valid length
            }
        ]

        signatures_with_invalid = Signatures(self.public_key, invalid_files)  # type: ignore

        # Verification should return False
        assert signatures_with_invalid.verify(hash_obj) is False

    def test_multiple_signatures(self):
        """Test adding and verifying multiple signatures."""
        # Use a fresh signatures object for this test
        signatures = Signatures(self.public_key, [])

        test_files = [b"file1 content", b"file2 content", b"file3 content"]

        hash_objects = []
        for content in test_files:
            hash_obj = hashlib.sha256(content)
            signature = self.private_key.sign_digest(hash_obj.digest())
            signatures.add_signature(hash_obj, signature)
            hash_objects.append(hash_obj)

        # Verify all signatures
        for hash_obj in hash_objects:
            assert signatures.verify(hash_obj) is True

        # Check total count
        signatures_dict = signatures.to_dict()
        assert len(signatures_dict["files"]) == len(test_files)

    def test_to_dict(self):
        """Test converting signatures to dictionary."""
        # Use a fresh signatures object for this test
        signatures = Signatures(self.public_key, [])

        # Add a signature
        test_data = b"test content for dict conversion"
        hash_obj = hashlib.sha256(test_data)
        signature = self.private_key.sign_digest(hash_obj.digest())
        signatures.add_signature(hash_obj, signature)

        signatures_dict = signatures.to_dict()

        # Verify structure
        assert "public_key" in signatures_dict
        assert "files" in signatures_dict
        assert isinstance(signatures_dict["public_key"], dict)
        assert isinstance(signatures_dict["files"], list)

        # Verify public key
        assert signatures_dict["public_key"] == self.public_key.to_dict()

        # Verify file entry
        assert len(signatures_dict["files"]) == 1
        file_entry = signatures_dict["files"][0]
        assert "sha256" in file_entry
        assert "signature" in file_entry

    def test_parse_signatures(self):
        """Test parsing signatures from dictionary."""
        # Create test data
        test_data = b"content for parsing test"
        hash_obj = hashlib.sha256(test_data)
        signature = self.private_key.sign_digest(hash_obj.digest())
        self.signatures.add_signature(hash_obj, signature)

        # Convert to dict and parse back
        signatures_dict = self.signatures.to_dict()
        parsed_signatures = Signatures.parse(signatures_dict)

        # Verify parsed object
        assert parsed_signatures.public_key.signer_info == self.public_key.signer_info
        assert parsed_signatures.verify(hash_obj) is True

    def test_load_from_file(self):
        """Test loading signatures from file-like object."""
        # Create test data
        test_data = b"content for file loading test"
        hash_obj = hashlib.sha256(test_data)
        signature = self.private_key.sign_digest(hash_obj.digest())
        self.signatures.add_signature(hash_obj, signature)

        # Create mock file
        signatures_dict = self.signatures.to_dict()
        mock_file = StringIO(json.dumps(signatures_dict))

        # Load from file
        loaded_signatures = Signatures.load(mock_file)

        # Verify loaded object
        assert loaded_signatures.public_key.signer_info == self.public_key.signer_info
        assert loaded_signatures.verify(hash_obj) is True

    def test_signature_map_caching(self):
        """Test that signature map is properly cached and cleared."""
        # Use a fresh signatures object for this test
        signatures = Signatures(self.public_key, [])

        # Add initial signature
        test_data1 = b"first file"
        hash_obj1 = hashlib.sha256(test_data1)
        signature1 = self.private_key.sign_digest(hash_obj1.digest())
        signatures.add_signature(hash_obj1, signature1)

        # Access signature map to cache it
        sig_map1 = signatures._signature_map()
        assert len(sig_map1) == 1

        # Add another signature (should clear cache)
        test_data2 = b"second file"
        hash_obj2 = hashlib.sha256(test_data2)
        signature2 = self.private_key.sign_digest(hash_obj2.digest())
        signatures.add_signature(hash_obj2, signature2)

        # Access signature map again (should be rebuilt)
        sig_map2 = signatures._signature_map()
        assert len(sig_map2) == 2
        assert hash_obj1.hexdigest() in sig_map2
        assert hash_obj2.hexdigest() in sig_map2

    def test_empty_signatures_collection(self):
        """Test behavior with empty signatures collection."""
        # Create a completely fresh signatures object for this test
        empty_signatures = Signatures(self.public_key, [])

        # to_dict should work with empty collection
        signatures_dict = empty_signatures.to_dict()
        assert len(signatures_dict["files"]) == 0

        # Verification should return False
        test_hash = hashlib.sha256(b"any content")
        assert empty_signatures.verify(test_hash) is False

    def test_initialization_with_existing_files(self):
        """Test creating Signatures with existing file list."""
        # Create test files list with proper typing
        from scrambleverse.sign import SignatureEntry

        test_files: list[SignatureEntry] = [
            {"sha256": "abc123", "signature": "c2lnbmF0dXJl"},  # base64 for "signature"
            {"sha256": "def456", "signature": "YW5vdGhlcg=="},  # base64 for "another"
        ]

        signatures = Signatures(self.public_key, test_files)
        signatures_dict = signatures.to_dict()

        assert len(signatures_dict["files"]) == 2
        assert signatures_dict["files"] == test_files

    def test_verify_with_different_hash_types(self):
        """Test verification with different hash algorithms (if supported)."""
        # Test with SHA256 (our primary algorithm)
        test_data = b"content for hash type test"
        sha256_hash = hashlib.sha256(test_data)
        signature = self.private_key.sign_digest(sha256_hash.digest())

        self.signatures.add_signature(sha256_hash, signature)

        # Verify with same algorithm
        verify_hash = hashlib.sha256(test_data)
        assert self.signatures.verify(verify_hash) is True

    def test_roundtrip_serialization(self):
        """Test complete roundtrip: create -> serialize -> parse -> verify."""
        # Create signatures with multiple files
        test_contents = [b"file1", b"file2", b"file3"]

        for content in test_contents:
            hash_obj = hashlib.sha256(content)
            signature = self.private_key.sign_digest(hash_obj.digest())
            self.signatures.add_signature(hash_obj, signature)

        # Serialize to dict
        original_dict = self.signatures.to_dict()

        # Parse back
        parsed_signatures = Signatures.parse(original_dict)

        # Verify all signatures still work
        for content in test_contents:
            hash_obj = hashlib.sha256(content)
            assert parsed_signatures.verify(hash_obj) is True

        # Verify serialized form is identical
        parsed_dict = parsed_signatures.to_dict()
        assert parsed_dict == original_dict

    def test_verify_string_vs_hash_object_consistency(self):
        """Test that verify works consistently with both string and hash object inputs."""
        # Use a fresh signatures object for this test
        signatures = Signatures(self.public_key, [])

        # Create test content and add signature
        test_data = b"Test content for string vs hash object verification"
        hash_obj = hashlib.sha256(test_data)
        signature = self.private_key.sign_digest(hash_obj.digest())
        signatures.add_signature(hash_obj, signature)

        # Get hex digest for string verification
        hex_digest = hash_obj.hexdigest()

        # Both verification methods should return True
        assert signatures.verify(hash_obj) is True
        assert signatures.verify(hex_digest) is True

        # Test with non-existent signature
        non_existent_hash = hashlib.sha256(b"Different content")
        non_existent_hex = non_existent_hash.hexdigest()

        # Both should return False for non-existent signatures
        assert signatures.verify(non_existent_hash) is False
        assert signatures.verify(non_existent_hex) is False

    def test_verify_method_edge_cases(self):
        """Test edge cases for the verify method after the fix."""
        # Use a fresh signatures object for this test
        signatures = Signatures(self.public_key, [])

        # Test with empty signatures collection
        test_hash = hashlib.sha256(b"any content")
        test_hex = test_hash.hexdigest()

        assert signatures.verify(test_hash) is False
        assert signatures.verify(test_hex) is False

        # Add a signature
        test_data = b"Edge case test content"
        hash_obj = hashlib.sha256(test_data)
        signature = self.private_key.sign_digest(hash_obj.digest())
        signatures.add_signature(hash_obj, signature)

        # Verify it works
        assert signatures.verify(hash_obj) is True
        assert signatures.verify(hash_obj.hexdigest()) is True

        # Test with malformed hex string (should return False, not crash)
        assert signatures.verify("not_a_valid_hex_digest") is False

        # Test with valid hex format but non-existent signature
        fake_hex = "a" * 64  # Valid hex format but non-existent signature
        assert signatures.verify(fake_hex) is False
