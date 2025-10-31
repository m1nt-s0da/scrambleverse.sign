import pytest
import tempfile
import json
import hashlib
from pathlib import Path
from unittest.mock import patch, MagicMock

from scrambleverse.sign import PrivateKey, PublicKey, Signatures, SignerInfo


class TestCLIIntegration:
    """Integration tests for CLI functionality without direct CLI testing."""

    def setup_method(self):
        """Set up test fixtures."""
        self.test_signer_info: SignerInfo = {"name": "CLI Test User"}
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_cli_workflow_simulation(self):
        """Test the complete CLI workflow by simulating the operations."""

        # Step 1: Simulate generate-private-key
        private_key = PrivateKey.generate(self.test_signer_info)
        passphrase = "test_cli_passphrase"
        encrypted_key = private_key.encrypt(passphrase)

        private_key_file = Path(self.temp_dir) / "private_key.json"
        with open(private_key_file, "w") as f:
            json.dump(encrypted_key.to_dict(), f, indent=2)

        # Step 2: Simulate generate-public-key
        def mock_passphrase_callback():
            return passphrase

        loaded_private_key = PrivateKey.from_file_and_decrypt_sync(
            str(private_key_file), mock_passphrase_callback
        )
        public_key = loaded_private_key.generate_public_key()

        public_key_file = Path(self.temp_dir) / "public_key.json"
        with open(public_key_file, "w") as f:
            json.dump(public_key.to_dict(), f, indent=2)

        # Step 3: Simulate sign-file
        test_files = []
        for i in range(3):
            test_file = Path(self.temp_dir) / f"document{i}.txt"
            content = f"Document {i} content for CLI test".encode()
            test_file.write_bytes(content)
            test_files.append((str(test_file), content))

        # Create signatures like the CLI would
        signatures = Signatures(public_key)
        for file_path, content in test_files:
            file_hash = hashlib.sha256(content)
            signature = loaded_private_key.sign_digest(file_hash.digest())
            signatures.add_signature(file_hash, signature)

        signatures_file = Path(self.temp_dir) / "signatures.json"
        with open(signatures_file, "w") as f:
            json.dump(signatures.to_dict(), f, indent=2)

        # Step 4: Simulate verify-file
        loaded_signatures = Signatures.from_file(str(signatures_file))

        for file_path, content in test_files:
            file_hash = hashlib.sha256(content)
            assert loaded_signatures.verify(file_hash) is True

        # Step 5: Simulate verify-public-key
        loaded_public_key = PublicKey.from_file(str(public_key_file))
        loaded_public_key.verify_self()  # Should not raise exception

        # Test file modification detection
        modified_file = Path(self.temp_dir) / "document0.txt"
        modified_file.write_bytes(b"Modified content")

        modified_hash = hashlib.sha256(b"Modified content")
        assert loaded_signatures.verify(modified_hash) is False

    def test_error_conditions_simulation(self):
        """Test error conditions that CLI would encounter."""

        # Test with invalid private key file
        invalid_key_file = Path(self.temp_dir) / "invalid_key.json"
        with open(invalid_key_file, "w") as f:
            json.dump({"invalid": "data"}, f)

        with pytest.raises(Exception):  # Should raise some form of parsing error
            PrivateKey.from_file(str(invalid_key_file))

        # Test with invalid public key
        private_key = PrivateKey.generate(self.test_signer_info)
        public_key = private_key.generate_public_key()

        # Corrupt public key data
        public_key_dict = public_key.to_dict()
        import base64

        public_key_dict["signature"] = base64.b64encode(b"x" * 64).decode(
            "ascii"
        )  # Valid length but wrong signature

        invalid_public_key_file = Path(self.temp_dir) / "invalid_public_key.json"
        with open(invalid_public_key_file, "w") as f:
            json.dump(public_key_dict, f)

        with pytest.raises(ValueError, match="Public key signature is invalid"):
            PublicKey.from_file(str(invalid_public_key_file))

    def test_file_operations_like_cli(self):
        """Test file operations similar to how CLI handles them."""

        # Create test scenario
        private_key = PrivateKey.generate(self.test_signer_info)
        public_key = private_key.generate_public_key()

        # Create multiple test files with different sizes
        test_cases = [
            ("small.txt", b"Small file content"),
            ("medium.txt", b"Medium file content " * 100),
            ("large.txt", b"Large file content " * 1000),
            ("binary.bin", bytes(range(256))),  # Binary data
        ]

        file_hashes = {}
        for filename, content in test_cases:
            file_path = Path(self.temp_dir) / filename
            file_path.write_bytes(content)

            # Simulate CLI chunked reading
            hash_obj = hashlib.sha256()
            chunk_size = 8192

            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    hash_obj.update(chunk)

            file_hashes[filename] = hash_obj

        # Create signatures for all files
        signatures = Signatures(public_key)
        for filename, hash_obj in file_hashes.items():
            signature = private_key.sign_digest(hash_obj.digest())
            signatures.add_signature(hash_obj, signature)

        # Verify all signatures
        for filename, hash_obj in file_hashes.items():
            assert signatures.verify(hash_obj) is True

        # Test serialization/deserialization
        signatures_dict = signatures.to_dict()
        loaded_signatures = Signatures.parse(signatures_dict)

        # Verify again with loaded signatures
        for filename, hash_obj in file_hashes.items():
            assert loaded_signatures.verify(hash_obj) is True

    def test_passphrase_scenarios(self):
        """Test different passphrase scenarios like CLI would handle."""

        # Test unencrypted key (empty passphrase)
        private_key = PrivateKey.generate(self.test_signer_info)

        unencrypted_file = Path(self.temp_dir) / "unencrypted_key.json"
        with open(unencrypted_file, "w") as f:
            json.dump(private_key.to_dict(), f)

        # Should load without needing passphrase
        loaded_unencrypted = PrivateKey.from_file(str(unencrypted_file))
        assert loaded_unencrypted._signer_info == self.test_signer_info

        # Test encrypted key with correct passphrase
        passphrase = "correct_passphrase"
        encrypted_key = private_key.encrypt(passphrase)

        encrypted_file = Path(self.temp_dir) / "encrypted_key.json"
        with open(encrypted_file, "w") as f:
            json.dump(encrypted_key.to_dict(), f)

        def correct_passphrase_callback():
            return passphrase

        loaded_encrypted = PrivateKey.from_file_and_decrypt_sync(
            str(encrypted_file), correct_passphrase_callback
        )
        assert loaded_encrypted._signer_info == self.test_signer_info

        # Test encrypted key with wrong passphrase
        def wrong_passphrase_callback():
            return "wrong_passphrase"

        with pytest.raises(Exception):  # Should raise decryption error
            PrivateKey.from_file_and_decrypt_sync(
                str(encrypted_file), wrong_passphrase_callback
            )

    def test_json_formatting_like_cli(self):
        """Test JSON formatting matches CLI output expectations."""

        # Generate keys and signatures
        private_key = PrivateKey.generate(self.test_signer_info)
        public_key = private_key.generate_public_key()
        signatures = Signatures(public_key)

        # Add a test signature
        test_content = b"Test content for JSON formatting"
        hash_obj = hashlib.sha256(test_content)
        signature = private_key.sign_digest(hash_obj.digest())
        signatures.add_signature(hash_obj, signature)

        # Test private key JSON format
        private_key_dict = private_key.to_dict()
        private_key_json = json.dumps(private_key_dict, indent=2)

        # Should be parseable
        parsed_private_dict = json.loads(private_key_json)
        assert parsed_private_dict == private_key_dict

        # Test public key JSON format
        public_key_dict = public_key.to_dict()
        public_key_json = json.dumps(public_key_dict, indent=2)

        parsed_public_dict = json.loads(public_key_json)
        assert parsed_public_dict == public_key_dict

        # Test signatures JSON format
        signatures_dict = signatures.to_dict()
        signatures_json = json.dumps(signatures_dict, indent=2)

        parsed_signatures_dict = json.loads(signatures_json)
        assert parsed_signatures_dict == signatures_dict

        # Verify all parsed objects work correctly
        reparsed_private = PrivateKey.parse(parsed_private_dict)
        reparsed_public = PublicKey.parse(parsed_public_dict)
        reparsed_signatures = Signatures.parse(parsed_signatures_dict)

        # Test functionality - ensure we have a PrivateKey, not EncryptedPrivateKey
        if isinstance(reparsed_private, PrivateKey):
            test_digest = hashlib.sha256(b"test").digest()
            sig = reparsed_private.sign_digest(test_digest)
            assert reparsed_public.verify_digest(test_digest, sig)

        assert reparsed_signatures.verify(hash_obj) is True
