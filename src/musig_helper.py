"""
Helper module to import MuSig2 functions from BIP-327.

This module handles the import path for BIP-327 MuSig2 reference implementation,
providing a clean interface for using MuSig2 functions.
"""

import importlib.util
import sys
from pathlib import Path

try:
    # Setup paths
    project_root = Path(__file__).parent.parent
    musig_reference_path = project_root / "bips" / "bip-0327" / "reference.py"

    # Verify path exists
    if not musig_reference_path.exists():
        raise ImportError(f"MuSig2 reference not found at {musig_reference_path}")

    # Load MuSig2 module with unique name to avoid conflicts
    spec = importlib.util.spec_from_file_location(
        "musig2_reference", musig_reference_path
    )
    if spec is None or spec.loader is None:
        raise ImportError("Failed to create module spec for MuSig2 reference")

    musig2_reference = importlib.util.module_from_spec(spec)
    sys.modules["musig2_reference"] = musig2_reference
    spec.loader.exec_module(musig2_reference)

    # Import required functions
    key_agg = musig2_reference.key_agg
    cbytes = musig2_reference.cbytes
    get_xonly_pk = musig2_reference.get_xonly_pk
    nonce_gen = musig2_reference.nonce_gen
    nonce_agg = musig2_reference.nonce_agg
    SessionContext = musig2_reference.SessionContext
    get_session_values = musig2_reference.get_session_values
    has_even_y = musig2_reference.has_even_y
    get_session_key_agg_coeff = musig2_reference.get_session_key_agg_coeff
    cpoint = musig2_reference.cpoint
    sign = musig2_reference.sign
    partial_sig_agg = musig2_reference.partial_sig_agg
    schnorr_verify = musig2_reference.schnorr_verify

except ImportError as e:
    raise ImportError(f"Failed to import MuSig2 components: {e}") from e

__all__ = [
    "key_agg",
    "cbytes",
    "get_xonly_pk",
    "nonce_gen",
    "nonce_agg",
    "SessionContext",
    "get_session_values",
    "has_even_y",
    "get_session_key_agg_coeff",
    "cpoint",
    "sign",
    "partial_sig_agg",
    "schnorr_verify",
]
