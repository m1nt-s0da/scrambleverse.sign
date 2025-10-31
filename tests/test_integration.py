import pytest
import tempfile
import os
import json
import hashlib
from pathlib import Path

from scrambleverse.sign import PrivateKey, PublicKey, Signatures, SignerInfo


class TestIntegration:
    def setup_method(self):
        """Set up test fixtures."""
        self.test_signer_info: SignerInfo = {"name": "Integration Test User"}
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_full_signing_workflow(self):
        """Test complete workflow: generate keys, sign files, verify signatures."""
        # Step 1: Generate private key
        private_key = PrivateKey.generate(self.test_signer_info)

        # Step 2: Generate public key
        public_key = private_key.generate_public_key()

        # Step 3: Create test files
        test_files = {
            "file1.txt": b"This is the content of file 1",
            "file2.txt": b"This is the content of file 2",
            "file3.txt": b"This is the content of file 3",
        }

        file_paths = []
        for filename, content in test_files.items():
            file_path = Path(self.temp_dir) / filename
            file_path.write_bytes(content)
            file_paths.append(str(file_path))

        # Step 4: Sign files
        signatures = Signatures(public_key)
        for file_path in file_paths:
            with open(file_path, "rb") as f:
                file_content = f.read()

            hash_obj = hashlib.sha256(file_content)
            signature = private_key.sign_digest(hash_obj.digest())
            signatures.add_signature(hash_obj, signature)

        # Step 5: Verify signatures
        for file_path in file_paths:
            with open(file_path, "rb") as f:
                file_content = f.read()

            hash_obj = hashlib.sha256(file_content)
            assert signatures.verify(hash_obj) is True

        # Step 6: Test with modified file (should fail verification)
        modified_file = Path(self.temp_dir) / "modified.txt"
        modified_file.write_bytes(b"This is different content")

        with open(modified_file, "rb") as f:
            modified_content = f.read()

        modified_hash = hashlib.sha256(modified_content)
        assert signatures.verify(modified_hash) is False

    def test_encrypted_key_workflow(self):
        """Test workflow with encrypted private key."""
        passphrase = "test_encryption_passphrase_123"

        # Generate and encrypt private key
        private_key = PrivateKey.generate(self.test_signer_info)
        encrypted_key = private_key.encrypt(passphrase)

        # Save encrypted key to file
        key_file = Path(self.temp_dir) / "encrypted_key.json"
        with open(key_file, "w", encoding="utf-8") as f:
            json.dump(encrypted_key.to_dict(), f, indent=2)

        # Load and decrypt key
        def test_passphrase_callback():
            return passphrase

        loaded_key = PrivateKey.from_file_and_decrypt_sync(
            str(key_file), test_passphrase_callback
        )

        # Verify keys are equivalent
        assert loaded_key._signer_info == private_key._signer_info

        # Test signing with loaded key
        test_digest = b"test message"
        digest = hashlib.sha256(test_digest).digest()

        original_signature = private_key.sign_digest(digest)
        loaded_signature = loaded_key.sign_digest(digest)

        # Signatures should be identical
        assert original_signature == loaded_signature

    def test_key_serialization_roundtrip(self):
        """Test complete serialization and deserialization of keys."""
        # Private key roundtrip
        private_key = PrivateKey.generate(self.test_signer_info)
        private_key_dict = private_key.to_dict()

        private_key_file = Path(self.temp_dir) / "private_key.json"
        with open(private_key_file, "w", encoding="utf-8") as f:
            json.dump(private_key_dict, f, indent=2)

        loaded_private_key = PrivateKey.from_file(str(private_key_file))
        assert loaded_private_key._signer_info == private_key._signer_info

        # Public key roundtrip
        public_key = private_key.generate_public_key()
        public_key_dict = public_key.to_dict()

        public_key_file = Path(self.temp_dir) / "public_key.json"
        with open(public_key_file, "w", encoding="utf-8") as f:
            json.dump(public_key_dict, f, indent=2)

        loaded_public_key = PublicKey.from_file(str(public_key_file))
        assert loaded_public_key.signer_info == public_key.signer_info

        # Verify consistency
        loaded_public_key.verify_self()

    def test_signatures_file_workflow(self):
        """Test complete signatures file workflow."""
        # Setup
        private_key = PrivateKey.generate(self.test_signer_info)
        public_key = private_key.generate_public_key()
        signatures = Signatures(public_key)

        # Create test file
        test_file = Path(self.temp_dir) / "document.txt"
        test_content = b"Important document content that needs verification"
        test_file.write_bytes(test_content)

        # Sign the file
        hash_obj = hashlib.sha256(test_content)
        signature = private_key.sign_digest(hash_obj.digest())
        signatures.add_signature(hash_obj, signature)

        # Save signatures to file
        signatures_file = Path(self.temp_dir) / "signatures.json"
        with open(signatures_file, "w", encoding="utf-8") as f:
            json.dump(signatures.to_dict(), f, indent=2)

        # Load signatures from file
        loaded_signatures = Signatures.from_file(str(signatures_file))

        # Verify the loaded signatures work
        verify_hash = hashlib.sha256(test_content)
        assert loaded_signatures.verify(verify_hash) is True

        # Verify public key integrity
        loaded_signatures.public_key.verify_self()

    def test_multiple_signers_scenario(self):
        """Test scenario with multiple signers (different keys)."""
        # Create two different signers
        signer1_info: SignerInfo = {"name": "Signer One"}
        signer2_info: SignerInfo = {"name": "Signer Two"}

        private_key1 = PrivateKey.generate(signer1_info)
        private_key2 = PrivateKey.generate(signer2_info)

        public_key1 = private_key1.generate_public_key()
        public_key2 = private_key2.generate_public_key()

        # Create test content
        test_content1 = b"Document signed by signer one"
        test_content2 = b"Document signed by signer two"

        hash_obj1 = hashlib.sha256(test_content1)
        hash_obj2 = hashlib.sha256(test_content2)

        # Each signer creates their own signatures collection
        signatures1 = Signatures(public_key1)
        signatures2 = Signatures(public_key2)

        signature1 = private_key1.sign_digest(hash_obj1.digest())
        signature2 = private_key2.sign_digest(hash_obj2.digest())

        signatures1.add_signature(hash_obj1, signature1)
        signatures2.add_signature(hash_obj2, signature2)

        # Both should verify with their respective collections and content
        assert signatures1.verify(hash_obj1) is True
        assert signatures2.verify(hash_obj2) is True

        # Test with hex string verification as well
        assert signatures1.verify(hash_obj1.hexdigest()) is True
        assert signatures2.verify(hash_obj2.hexdigest()) is True

        # Cross-verification should work with public keys
        assert public_key1.verify_digest(hash_obj1.digest(), signature1)
        assert public_key2.verify_digest(hash_obj2.digest(), signature2)

        # Wrong combinations should fail
        assert not public_key1.verify_digest(hash_obj1.digest(), signature2)
        assert not public_key2.verify_digest(hash_obj2.digest(), signature1)

        # Test that the wrong signer cannot verify the other's document
        assert signatures1.verify(hash_obj2) is False
        assert signatures2.verify(hash_obj1) is False

        # Test string-based verification for wrong documents
        assert signatures1.verify(hash_obj2.hexdigest()) is False
        assert signatures2.verify(hash_obj1.hexdigest()) is False

    def test_file_modification_detection(self):
        """Test that file modifications are properly detected."""
        private_key = PrivateKey.generate(self.test_signer_info)
        public_key = private_key.generate_public_key()
        signatures = Signatures(public_key)

        # Create and sign original file
        test_file = Path(self.temp_dir) / "document.txt"
        original_content = b"Original document content"
        test_file.write_bytes(original_content)

        original_hash = hashlib.sha256(original_content)
        signature = private_key.sign_digest(original_hash.digest())
        signatures.add_signature(original_hash, signature)

        # Verify original content
        verify_hash = hashlib.sha256(original_content)
        assert signatures.verify(verify_hash) is True

        # Modify file content
        modified_content = b"Modified document content"
        test_file.write_bytes(modified_content)

        # Verification with modified content should fail
        modified_hash = hashlib.sha256(modified_content)
        assert signatures.verify(modified_hash) is False

        # Original hash verification should still work
        assert signatures.verify(original_hash) is True

    def test_large_file_handling(self):
        """Test handling of larger files (chunked reading simulation)."""
        private_key = PrivateKey.generate(self.test_signer_info)
        public_key = private_key.generate_public_key()
        signatures = Signatures(public_key)

        # Create a larger test file
        large_content = b"This is a test pattern. " * 1000  # ~24KB
        large_file = Path(self.temp_dir) / "large_document.bin"
        large_file.write_bytes(large_content)

        # Simulate chunked reading (like in the CLI)
        hash_obj = hashlib.sha256()
        chunk_size = 8192

        with open(large_file, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hash_obj.update(chunk)

        # Sign the hash
        signature = private_key.sign_digest(hash_obj.digest())
        signatures.add_signature(hash_obj, signature)

        # Verify by re-reading the file
        verify_hash = hashlib.sha256()
        with open(large_file, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                verify_hash.update(chunk)

        assert signatures.verify(verify_hash) is True

        # Also verify direct comparison
        direct_hash = hashlib.sha256(large_content)
        assert signatures.verify(direct_hash) is True

    @pytest.mark.asyncio
    async def test_async_key_loading(self):
        """Test asynchronous key loading functionality."""
        passphrase = "async_test_passphrase"

        # Create encrypted key
        private_key = PrivateKey.generate(self.test_signer_info)
        encrypted_key = private_key.encrypt(passphrase)

        # Save to file
        key_file = Path(self.temp_dir) / "async_key.json"
        with open(key_file, "w", encoding="utf-8") as f:
            json.dump(encrypted_key.to_dict(), f)

        # Test async loading
        async def async_passphrase_callback():
            return passphrase

        loaded_key = await PrivateKey.from_file_and_decrypt(
            str(key_file), async_passphrase_callback
        )

        # Verify loaded key works
        assert loaded_key._signer_info == private_key._signer_info

        # Test signing capability
        test_digest = b"async test message"
        digest = hashlib.sha256(test_digest).digest()

        signature = loaded_key.sign_digest(digest)
        assert len(signature) > 0

    def test_verify_method_with_string_and_hash_objects(self):
        """Test that the fixed verify method works correctly with both string and hash object inputs."""
        private_key = PrivateKey.generate(self.test_signer_info)
        public_key = private_key.generate_public_key()
        signatures = Signatures(public_key)

        # Create multiple test files
        test_files = [
            b"First document content",
            b"Second document content",
            b"Third document content",
        ]

        hash_objects = []
        hex_digests = []

        # Sign all files
        for content in test_files:
            hash_obj = hashlib.sha256(content)
            signature = private_key.sign_digest(hash_obj.digest())
            signatures.add_signature(hash_obj, signature)

            hash_objects.append(hash_obj)
            hex_digests.append(hash_obj.hexdigest())

        # Test verification with hash objects
        for hash_obj in hash_objects:
            assert signatures.verify(hash_obj) is True

        # Test verification with hex strings
        for hex_digest in hex_digests:
            assert signatures.verify(hex_digest) is True

        # Test non-existent signatures
        non_existent_hash = hashlib.sha256(b"Non-existent content")
        non_existent_hex = non_existent_hash.hexdigest()

        assert signatures.verify(non_existent_hash) is False
        assert signatures.verify(non_existent_hex) is False

        # Test cross-verification consistency
        for i, content in enumerate(test_files):
            # Create fresh hash object for same content
            fresh_hash = hashlib.sha256(content)

            # Both methods should give same result
            assert signatures.verify(fresh_hash) == signatures.verify(hex_digests[i])
            assert signatures.verify(fresh_hash) is True
