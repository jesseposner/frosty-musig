# FROST + MuSig2 Nested Signing

A Python implementation of nested threshold signatures combining FROST (Flexible Round-Optimized Schnorr Threshold signatures) with MuSig2 multi-signatures. This allows a threshold subset of FROST participants to act as a single MuSig2 signer.

⚠️ **WARNING**: This implementation is for demonstration and research purposes only. It has not been audited and should not be used in production systems.

## Overview

This project implements a novel nested signing protocol where:
- A group uses **FROST** to create a `t-of-n` threshold signature scheme
- The FROST group acts as a single participant in a **MuSig2** multi-signature
- The final signature is a standard Schnorr signature verifiable with the aggregated public key

### Use Cases

- **Enhanced security**: An entity (using FROST internally) can participate in protocols that use MuSig2
- **Interoperability**: FROST groups can seamlessly interact with standard MuSig2 implementations
- **Lightning**: Distributed security for either side of a Taproot Lightning channel

## Documentation

The `docs/` directory contains reference papers:
- `2020-1261.pdf` - The MuSig2 protocol
- `2023-899.pdf` - The Olaf/FROST3 protocol
- `FROSTyMuSig.pdf` - Formal specification of the nested signing scheme

## Project Structure

```
├── src/                    # Source code
│   ├── frost_helper.py     # FROST protocol import helper
│   ├── musig_helper.py     # MuSig2 protocol import helper
│   └── nested_signing.py   # Nested signing implementation
├── tests/                  # Test suite
│   └── test_integration.py # End-to-end integration tests
├── bips/                   # Bitcoin Improvement Proposals (BIP-327 for MuSig2)
├── frost/                  # FROST reference implementation
└── docs/                   # Academic papers and specifications
```

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd frosty-musig
```

2. Install development dependencies:
```bash
make install-dev
```

Or manually:
```bash
pip install -r requirements-dev.txt
```

## Usage

### Running the Demo

The project includes a demonstration of the complete nested signing protocol:

```bash
python3 src/nested_signing.py
```

This will:
1. Generate FROST keys for a 2-of-3 threshold scheme
2. Generate another MuSig2 participant's keys
3. Aggregate the keys using MuSig2
4. Perform the nested signing protocol
5. Verify the final signature

### Running Tests

Run the integration test suite:

```bash
make test
```

Or manually:
```bash
python3 tests/test_integration.py
```

### Code Quality

Run linting and type checking:

```bash
make check  # Runs both lint and type-check
make lint   # Run ruff linter with auto-fix
make type-check  # Run mypy type checker
```

Format code:

```bash
make format
```

Run everything (format, check, test):

```bash
make all
```

## Implementation Details

### Key Components

1. **FROST Helper** (`src/frost_helper.py`)
   - Imports FROST functions from the signing BIP reference implementation

2. **MuSig2 Helper** (`src/musig_helper.py`)
   - Imports MuSig2 functions from BIP-327 reference

3. **Nested Signing** (`src/nested_signing.py`)
   - `nested_frost_sign()`: FROST participants create partial signatures
   - `nested_frost_partial_sig_agg()`: Aggregates FROST partial signatures
   - Complete demo showing the full protocol flow

## Development

### Project Configuration

- **Linting**: Configured with Ruff (see `pyproject.toml`)
- **Type Checking**: MyPy with Python 3.8+ type hints
- **Testing**: Integration tests with deterministic test vectors

### Contributing

1. Ensure all tests pass: `make test`
2. Check code quality: `make check`
3. Format code: `make format`

## References

- [FROST](https://eprint.iacr.org/2020/852): Flexible Round-Optimized Schnorr Threshold Signatures
- [OLAF/FROST3](https://eprint.iacr.org/2023/899): Improvements to FROST
- [MuSig2](https://eprint.iacr.org/2020/1261): Simple Two-Round Schnorr Multi-Signatures
- [BIP-327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki): MuSig2 for Bitcoin
- [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki): Schnorr Signatures for secp256k1
- [Signing BIP](https://github.com/siv2r/bip-frost-signing): FROST Signing for Bitcoin 

## License

This project uses reference implementations from:
- FROST Signing BIP reference implementation (frost/)
- BIP-327 MuSig2 reference (bips/bip-0327/)

Please refer to the individual directories for their respective licenses.

## Disclaimer

This is experimental software intended for research and educational purposes. Do not use in production environments without proper security audits and review.