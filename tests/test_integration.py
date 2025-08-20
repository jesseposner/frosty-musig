"""
Integration tests for FROST + MuSig2 nested signing.

This test ensures the complete protocol works end-to-end.
"""

import sys
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import secrets
from hashlib import sha256

from frost_helper import G, Scalar, generate_frost_keys
from frost_helper import SessionContext as FrostSessionContext
from frost_helper import cpoint as frost_cpoint
from frost_helper import get_session_values as frost_get_session_values
from frost_helper import nonce_agg as frost_nonce_agg
from frost_helper import nonce_gen as frost_nonce_gen
from musig_helper import SessionContext as MusigSessionContext
from musig_helper import cbytes as musig_cbytes
from musig_helper import get_xonly_pk as musig_get_xonly_pk
from musig_helper import key_agg
from musig_helper import nonce_agg as musig_nonce_agg
from musig_helper import nonce_gen as musig_nonce_gen
from musig_helper import partial_sig_agg as musig_partial_sig_agg
from musig_helper import schnorr_verify as musig_schnorr_verify
from musig_helper import sign as musig_sign
from nested_signing import nested_frost_partial_sig_agg, nested_frost_sign


def test_nested_signing_protocol():
    """Test the complete FROST + MuSig2 nested signing protocol."""
    print("Running integration test for nested signing protocol...")

    # Configuration
    frost_total_participants = 3
    frost_threshold = 2

    # Step 1: FROST key generation
    frost_pk, frost_identifiers, frost_ser_secshares, frost_ser_pubshares = (
        generate_frost_keys(
            frost_total_participants,
            frost_threshold,
        )
    )
    assert len(frost_ser_secshares) == frost_total_participants
    assert len(frost_ser_pubshares) == frost_total_participants
    assert len(frost_identifiers) == frost_total_participants
    print("✓ FROST key generation successful")

    # Step 2: Generate other MuSig2 participant key
    other_secret = Scalar.from_bytes_wrapping(secrets.token_bytes(32))
    other_pubkey_point = other_secret * G
    other_pk_bytes = other_pubkey_point.to_bytes_compressed()
    print("✓ Other participant key generation successful")

    # Step 3: MuSig2 key aggregation
    key_agg_ctx = key_agg([frost_pk, other_pk_bytes])
    agg_bytes = musig_cbytes(key_agg_ctx.Q)
    agg_xonly = musig_get_xonly_pk(key_agg_ctx)
    print("✓ MuSig2 key aggregation successful")

    # Step 4: Message to sign
    message_text = b"Example message to sign"
    message = sha256(message_text).digest()

    # Step 5: FROST nonce generation for signing quorum
    signing_quorum = [0, 2]  # Use participants 0 and 2
    secnonce_0, pubnonce_0 = frost_nonce_gen(
        frost_ser_secshares[0], frost_ser_pubshares[0], agg_xonly, message, agg_bytes
    )
    secnonce_2, pubnonce_2 = frost_nonce_gen(
        frost_ser_secshares[2], frost_ser_pubshares[2], agg_xonly, message, agg_bytes
    )
    frost_aggnonce = frost_nonce_agg([pubnonce_0, pubnonce_2], signing_quorum)
    print("✓ FROST nonce generation successful")

    # Step 6: Create FROST session context
    signing_pubshares = [frost_ser_pubshares[0], frost_ser_pubshares[2]]
    frost_session_ctx = FrostSessionContext(
        frost_aggnonce,
        signing_quorum,
        signing_pubshares,
        [],
        [],  # No tweaks
        message,
    )

    # Step 7: Tweak FROST aggregate nonce for MuSig2
    (_, _, _, b_frost, _, _) = frost_get_session_values(frost_session_ctx)
    frost_r_2 = frost_cpoint(frost_aggnonce[33:])
    tweaked_frost_r_2 = b_frost * frost_r_2
    tweaked_frost_aggnonce = (
        frost_aggnonce[:33] + tweaked_frost_r_2.to_bytes_compressed()
    )
    print("✓ FROST nonce tweaking successful")

    # Step 8: Generate other MuSig2 participant nonce
    other_secnonce, other_pubnonce = musig_nonce_gen(
        other_secret.to_bytes(), other_pk_bytes, agg_xonly, message, None
    )

    # Step 9: Aggregate MuSig2 nonces
    musig_aggnonce = musig_nonce_agg([tweaked_frost_aggnonce, other_pubnonce])
    print("✓ MuSig2 nonce aggregation successful")

    # Step 10: Create MuSig2 session context
    musig_session_ctx = MusigSessionContext(
        musig_aggnonce,
        [frost_pk, other_pk_bytes],
        [],
        [],  # No tweaks
        message,
    )

    # Step 11: FROST participants create partial signatures
    # Make copies of secnonces since they get zeroed out
    secnonce_0_copy = bytearray(secnonce_0)
    secnonce_2_copy = bytearray(secnonce_2)

    psig_frost_1 = nested_frost_sign(
        secnonce_0_copy, frost_ser_secshares[0], 0, frost_session_ctx, musig_session_ctx
    )
    psig_frost_2 = nested_frost_sign(
        secnonce_2_copy, frost_ser_secshares[2], 2, frost_session_ctx, musig_session_ctx
    )
    print("✓ FROST partial signatures created")

    # Step 12: Aggregate FROST partial signatures
    frost_psig = nested_frost_partial_sig_agg(
        [psig_frost_1, psig_frost_2], [0, 2], frost_session_ctx
    )
    assert len(frost_psig) == 64  # 32 bytes R + 32 bytes s
    print("✓ FROST signature aggregation successful")

    # Step 13: Other MuSig2 participant creates signature
    other_psig = musig_sign(other_secnonce, other_secret.to_bytes(), musig_session_ctx)
    print("✓ Other participant signature created")

    # Step 14: Final MuSig2 signature aggregation
    # Note: frost_psig[32:] extracts just the s value (skipping R)
    sig = musig_partial_sig_agg([frost_psig[32:], other_psig], musig_session_ctx)
    assert len(sig) == 64  # Complete Schnorr signature
    print("✓ Final MuSig2 signature aggregation successful")

    # Step 15: Verify the final signature
    is_valid = musig_schnorr_verify(message, agg_xonly, sig)
    assert is_valid, "Signature verification failed!"
    print("✓ Signature verification PASSED")

    return True


def test_deterministic_signing():
    """Test with fixed seeds to ensure reproducible results."""
    print("\nRunning deterministic test...")

    # Use fixed seed for reproducibility
    import random

    random.seed(42)

    # Configuration
    frost_total_participants = 3
    frost_threshold = 2

    # Generate keys with fixed randomness
    frost_pk, frost_identifiers, frost_ser_secshares, frost_ser_pubshares = (
        generate_frost_keys(
            frost_total_participants,
            frost_threshold,
        )
    )

    # Create a deterministic other participant
    other_secret = Scalar.from_bytes_wrapping(b"test" * 8)  # 32 bytes
    other_pubkey_point = other_secret * G
    other_pk_bytes = other_pubkey_point.to_bytes_compressed()

    # Aggregate keys
    key_agg_ctx = key_agg([frost_pk, other_pk_bytes])
    agg_xonly = musig_get_xonly_pk(key_agg_ctx)

    # Fixed message
    message = sha256(b"Test message").digest()

    # Run the signing protocol
    signing_quorum = [0, 2]

    # Generate nonces
    secnonce_0, pubnonce_0 = frost_nonce_gen(
        frost_ser_secshares[0],
        frost_ser_pubshares[0],
        agg_xonly,
        message,
        musig_cbytes(key_agg_ctx.Q),
    )
    secnonce_2, pubnonce_2 = frost_nonce_gen(
        frost_ser_secshares[2],
        frost_ser_pubshares[2],
        agg_xonly,
        message,
        musig_cbytes(key_agg_ctx.Q),
    )

    # Create contexts and sign
    frost_aggnonce = frost_nonce_agg([pubnonce_0, pubnonce_2], signing_quorum)
    signing_pubshares = [frost_ser_pubshares[0], frost_ser_pubshares[2]]
    frost_session_ctx = FrostSessionContext(
        frost_aggnonce,
        signing_quorum,
        signing_pubshares,
        [],
        [],
        message,
    )

    # Tweak and create MuSig2 context
    (_, _, _, b_frost, _, _) = frost_get_session_values(frost_session_ctx)
    frost_r_2 = frost_cpoint(frost_aggnonce[33:])
    tweaked_frost_r_2 = b_frost * frost_r_2
    tweaked_frost_aggnonce = (
        frost_aggnonce[:33] + tweaked_frost_r_2.to_bytes_compressed()
    )

    other_secnonce, other_pubnonce = musig_nonce_gen(
        other_secret.to_bytes(), other_pk_bytes, agg_xonly, message, None
    )

    musig_aggnonce = musig_nonce_agg([tweaked_frost_aggnonce, other_pubnonce])
    musig_session_ctx = MusigSessionContext(
        musig_aggnonce,
        [frost_pk, other_pk_bytes],
        [],
        [],
        message,
    )

    # Sign
    psig_frost_1 = nested_frost_sign(
        bytearray(secnonce_0),
        frost_ser_secshares[0],
        0,
        frost_session_ctx,
        musig_session_ctx,
    )
    psig_frost_2 = nested_frost_sign(
        bytearray(secnonce_2),
        frost_ser_secshares[2],
        2,
        frost_session_ctx,
        musig_session_ctx,
    )

    frost_psig = nested_frost_partial_sig_agg(
        [psig_frost_1, psig_frost_2], [0, 2], frost_session_ctx
    )

    other_psig = musig_sign(other_secnonce, other_secret.to_bytes(), musig_session_ctx)
    sig = musig_partial_sig_agg([frost_psig[32:], other_psig], musig_session_ctx)

    # Verify
    is_valid = musig_schnorr_verify(message, agg_xonly, sig)
    assert is_valid, "Deterministic signature verification failed!"
    print("✓ Deterministic test PASSED")

    return True


if __name__ == "__main__":
    print("=" * 60)
    print("FROST + MuSig2 Nested Signing Integration Tests")
    print("=" * 60)

    try:
        # Run main integration test
        test_nested_signing_protocol()

        # Run deterministic test
        test_deterministic_signing()

        print("\n" + "=" * 60)
        print("✅ ALL INTEGRATION TESTS PASSED!")
        print("=" * 60)

    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        raise
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}")
        raise
