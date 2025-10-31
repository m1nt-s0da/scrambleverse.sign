# Tests for scrambleverse-sign

This directory contains comprehensive tests for the scrambleverse-sign package.

## Test Structure

- `test_private_key.py` - Tests for private key functionality including generation, encryption/decryption, and serialization
- `test_public_key.py` - Tests for public key functionality including verification and serialization  
- `test_signatures.py` - Tests for signature creation, verification, and file operations
- `test_integration.py` - Integration tests covering complete workflows
- `test_cli.py` - Tests simulating CLI operations and workflows

## Running Tests

### Prerequisites

Make sure you have the test dependencies installed:

```bash
pip install -r requirements-test.txt
```

Or if using pipenv:

```bash
pipenv install --dev
```

### Basic Test Execution

Run all tests:
```bash
pytest
```

Run tests with coverage:
```bash
pytest --cov=scrambleverse.sign --cov-report=html
```

Run specific test files:
```bash
pytest tests/test_private_key.py
pytest tests/test_public_key.py
pytest tests/test_signatures.py
pytest tests/test_integration.py
pytest tests/test_cli.py
```

Run specific test classes:
```bash
pytest tests/test_private_key.py::TestPrivateKey
pytest tests/test_public_key.py::TestPublicKey
```

Run specific test methods:
```bash
pytest tests/test_private_key.py::TestPrivateKey::test_private_key_generation
```

### Test Filtering

Run only fast tests (exclude slow integration tests):
```bash
pytest -m "not slow"
```

Run only unit tests:
```bash
pytest -m unit
```

Run only integration tests:
```bash
pytest -m integration
```

### Verbose Output

For detailed test output:
```bash
pytest -v
```

For extra verbose output with print statements:
```bash
pytest -v -s
```

## Test Coverage

The tests aim to provide comprehensive coverage of:

1. **Core Functionality**
   - Key generation and management
   - Encryption/decryption operations
   - Digital signature creation and verification
   - File operations and serialization

2. **Error Handling**
   - Invalid input validation
   - Cryptographic error conditions
   - File I/O error scenarios
   - Type safety and validation

3. **Integration Scenarios**
   - Complete signing workflows
   - Key file management
   - Multi-file operations
   - Cross-platform compatibility

4. **CLI Simulation**
   - Command-line workflow simulation
   - File format validation
   - User interaction scenarios

## Test Data

Tests use temporary directories and files that are automatically cleaned up after each test. No persistent test data is created in the repository.

## Performance

Tests are designed to run quickly while still providing thorough coverage. Integration tests may take slightly longer as they test complete workflows with file I/O operations.

## Contributing

When adding new features:

1. Add corresponding unit tests in the appropriate test file
2. Add integration tests if the feature affects workflows
3. Ensure all tests pass before submitting changes
4. Maintain or improve test coverage
5. Add appropriate test markers (unit, integration, slow) if needed