"""
Helper module to import FROST functions.

This module handles the complex import paths for FROST reference implementation
and its dependencies, providing a clean interface for using FROST functions.
"""

import importlib.util
import sys
from pathlib import Path

try:
    # Setup paths
    project_root = Path(__file__).parent.parent
    frost_reference_path = project_root / "frost" / "reference" / "reference.py"
    frost_base_path = project_root / "frost" / "reference"
    secp256k1lab_path = frost_base_path / "secp256k1lab" / "src"

    # Verify paths exist
    if not frost_reference_path.exists():
        raise ImportError(f"FROST reference not found at {frost_reference_path}")

    # Add dependencies to path (required for FROST's internal imports)
    for path in [secp256k1lab_path, frost_base_path]:
        path_str = str(path)
        if path_str not in sys.path:
            sys.path.insert(0, path_str)

    # Load FROST module with unique name to avoid conflicts
    spec = importlib.util.spec_from_file_location(
        "frost_reference", frost_reference_path
    )
    if spec is None or spec.loader is None:
        raise ImportError("Failed to create module spec for FROST reference")

    frost_reference = importlib.util.module_from_spec(spec)
    sys.modules["frost_reference"] = frost_reference
    spec.loader.exec_module(frost_reference)

    # Import required functions
    generate_frost_keys = frost_reference.generate_frost_keys
    nonce_gen = frost_reference.nonce_gen
    nonce_agg = frost_reference.nonce_agg
    SessionContext = frost_reference.SessionContext
    get_session_values = frost_reference.get_session_values
    cpoint = frost_reference.cpoint

    # Import secp256k1lab utilities
    from secp256k1lab.secp256k1 import G, Scalar  # noqa: E402

except ImportError as e:
    raise ImportError(f"Failed to import FROST components: {e}") from e

__all__ = [
    "generate_frost_keys",
    "Scalar",
    "G",
    "nonce_gen",
    "nonce_agg",
    "SessionContext",
    "get_session_values",
    "cpoint",
]
