"""
FROST + MuSig2 Nested Signing

WARNING: This is for demonstration purposes only, not for production use.
"""

import secrets
from hashlib import sha256
from typing import List

from frost_helper import (
    GE,
    G,
    Scalar,
    generate_frost_keys,
    get_session_interpolating_value,
    session_has_signer_pubshare,
)
from frost_helper import InvalidContributionError as FrostInvalidContributionError
from frost_helper import SessionContext as FrostSessionContext
from frost_helper import cbytes as frost_cbytes
from frost_helper import cpoint as frost_cpoint
from frost_helper import get_session_values as frost_get_session_values
from frost_helper import int_from_bytes as frost_int_from_bytes
from frost_helper import nonce_agg as frost_nonce_agg
from frost_helper import nonce_gen as frost_nonce_gen
from musig_helper import SessionContext as MusigSessionContext
from musig_helper import cbytes as musig_cbytes
from musig_helper import cpoint as musig_cpoint
from musig_helper import get_session_key_agg_coeff, key_agg
from musig_helper import get_session_values as musig_get_session_values
from musig_helper import get_xonly_pk as musig_get_xonly_pk
from musig_helper import has_even_y as musig_has_even_y
from musig_helper import nonce_agg as musig_nonce_agg
from musig_helper import nonce_gen as musig_nonce_gen
from musig_helper import partial_sig_agg as musig_partial_sig_agg
from musig_helper import schnorr_verify as musig_schnorr_verify
from musig_helper import sign as musig_sign


def nested_frost_sign(
    secnonce: bytearray,
    secshare: bytes,
    my_id: int,
    frost_session_ctx: FrostSessionContext,
    musig_session_ctx: MusigSessionContext,
) -> bytes:
    if not 0 <= my_id < 2**32:
        raise ValueError("The signer's participant identifier is out of range")

    (Q_frost, gacc_frost, _, b_frost, R_frost, e_frost) = frost_get_session_values(  # noqa N806
        frost_session_ctx
    )
    (Q_musig, gacc_musig, _, b_musig, R_musig, e_musig) = musig_get_session_values(  # noqa N806
        musig_session_ctx
    )

    try:
        k_1_ = Scalar.from_bytes_checked(secnonce[0:32])
        if k_1_ == 0:  # treat zero exactly like any other bad input
            raise ValueError
    except ValueError as e:
        raise ValueError("first secnonce value is out of range.") from e
    try:
        k_2_ = Scalar.from_bytes_checked(secnonce[32:64])
        if k_2_ == 0:  # treat zero exactly like any other bad input
            raise ValueError
    except ValueError as e:
        raise ValueError("second secnonce value is out of range.") from e

    # Overwrite the secnonce argument with zeros such that subsequent calls of
    # sign with the same secnonce raise a ValueError.
    secnonce[:] = bytearray(b"\x00" * 64)

    # Apply nonce negation based on MuSig2's R (not FROST's R)
    # This ensures consistency with the MuSig2 aggregated nonce
    k_1 = k_1_ if musig_has_even_y(R_musig) else -k_1_
    k_2 = k_2_ if musig_has_even_y(R_musig) else -k_2_

    d_ = frost_int_from_bytes(secshare)
    if not 0 < d_ < GE.ORDER:
        raise ValueError("The signer's secret share value is out of range.")
    P = d_ * G  # noqa N806
    assert not P.infinity
    pubshare = frost_cbytes(P)
    if not session_has_signer_pubshare(frost_session_ctx, pubshare):
        raise ValueError(
            "The signer's pubshare must be included in the list of pubshares."
        )
    a_frost = get_session_interpolating_value(frost_session_ctx, my_id)
    Q_frost_bytes = Q_frost.to_bytes_compressed()  # noqa N806
    Q_frost_point = musig_cpoint(Q_frost_bytes)  # noqa N806
    a_musig = get_session_key_agg_coeff(musig_session_ctx, Q_frost_point)
    g_musig = Scalar(1) if musig_has_even_y(Q_musig) else Scalar(-1)
    d = g_musig * gacc_musig * d_
    s = k_1 + b_frost * b_musig * k_2 + e_musig * a_musig * a_frost * d
    psig: bytes = s.to_bytes()
    R_s1 = k_1_ * G  # noqa N806
    R_s2 = k_2_ * G  # noqa N806
    assert not R_s1.infinity
    assert not R_s2.infinity
    _pubnonce = frost_cbytes(R_s1) + frost_cbytes(R_s2)
    # Optional correctness check. The result of signing should pass signature
    # verification.
    # assert partial_sig_verify_internal(psig, my_id, pubnonce, pubshare, session_ctx)
    return psig


def nested_frost_partial_sig_agg(
    psigs: List[bytes],
    ids: List[int],
    frost_session_ctx: FrostSessionContext,
    musig_session_ctx: MusigSessionContext,
) -> bytes:
    if len(psigs) != len(ids):
        raise ValueError("The psigs and ids arrays must have the same length.")
    (_, _, tacc_frost, _, _, _) = frost_get_session_values(frost_session_ctx)  # noqa N806
    (Q_musig, _, _, _, _, e_musig) = musig_get_session_values(musig_session_ctx)  # noqa N806
    s = Scalar(0)
    for my_id, psig in zip(ids, psigs):
        s_i = frost_int_from_bytes(psig)
        try:
            s_i = Scalar.from_bytes_checked(psig)
        except ValueError as e:
            raise FrostInvalidContributionError(my_id, "psig") from e
        s = s + s_i
    g_musig = Scalar(1) if musig_has_even_y(Q_musig) else Scalar(-1)
    s = s + e_musig * g_musig * tacc_frost
    s_bytes: bytes = s.to_bytes()
    return s_bytes


def demo():
    frost_total_participants = 3
    frost_threshold = 2
    print("FROST + MuSig2 Key Generation Demo")
    print("=" * 50)

    # Step 1: FROST key generation
    print("\n1. FROST Key Generation")
    print("-" * 30)
    frost_pk, frost_identifiers, frost_ser_secshares, frost_ser_pubshares = (
        generate_frost_keys(
            frost_total_participants,  # max_participants
            frost_threshold,  # min_participants
        )
    )
    print("FROST Key Generation Complete")
    print("=" * 50)
    print(f"Threshold: {frost_threshold} of {frost_total_participants}")
    print(f"Group Public Key: {frost_pk.hex()}")
    print(f"Number of shares: {len(frost_ser_secshares)}")
    print(f"Participant IDs: {frost_identifiers}")

    # Step 2: Generate other MuSig2 participant key
    print("\n2. Generate Other MuSig2 Participant")
    other_secret = Scalar.from_bytes_wrapping(secrets.token_bytes(32))
    other_pubkey_point = other_secret * G
    print(f"Public Key: {other_pubkey_point.to_bytes_compressed().hex()}")

    # Step 3: MuSig2 key aggregation
    print("\n3. MuSig2 Key Aggregation")
    print("-" * 30)
    other_pk_bytes = other_pubkey_point.to_bytes_compressed()
    key_agg_ctx = key_agg([frost_pk, other_pk_bytes])
    print("Aggregated key created successfully")
    agg_bytes = musig_cbytes(key_agg_ctx.Q)
    print(f"Public Key: {agg_bytes.hex()}")
    agg_xonly = musig_get_xonly_pk(key_agg_ctx)
    print(f"X-only: {agg_xonly.hex()}")

    # Step 4: Nonce generation
    print("\n4. Nonce Generation")
    print("-" * 30)
    message_text = b"Example message to sign"
    message = sha256(message_text).digest()  # 32-byte hash
    print(f"Message: {message_text.decode()}")
    print(f"Message hash: {message.hex()}")

    # Generate FROST nonces for a signing quorum (2 of 3)
    signing_quorum = [0, 2]  # Use participants 0 and 2 (0-indexed)
    print(f"FROST signing quorum: participants {signing_quorum}")
    secnonce_0, pubnonce_0 = frost_nonce_gen(
        frost_ser_secshares[0], frost_ser_pubshares[0], agg_xonly, message, agg_bytes
    )
    secnonce_2, pubnonce_2 = frost_nonce_gen(
        frost_ser_secshares[2], frost_ser_pubshares[2], agg_xonly, message, agg_bytes
    )
    frost_aggnonce = frost_nonce_agg([pubnonce_0, pubnonce_2], signing_quorum)
    print(f"FROST aggregate nonce generated: {frost_aggnonce.hex()}")
    signing_pubshares = [frost_ser_pubshares[0], frost_ser_pubshares[2]]
    frost_session_ctx = FrostSessionContext(
        frost_aggnonce,
        signing_quorum,
        signing_pubshares,
        [],
        [],  # No tweaks
        message,
    )
    (_, _, _, b_frost, _, _) = frost_get_session_values(frost_session_ctx)
    frost_r_2 = frost_cpoint(frost_aggnonce[33:])
    tweaked_frost_r_2 = b_frost * frost_r_2
    tweaked_frost_aggnonce = (
        frost_aggnonce[:33] + tweaked_frost_r_2.to_bytes_compressed()
    )
    print(f"b_frost: {b_frost}")
    print(f"tweaked_frost_aggnonce: {tweaked_frost_aggnonce.hex()}")

    # Generate other MuSig2 nonce
    other_secnonce, other_pubnonce = musig_nonce_gen(
        other_secret.to_bytes(), other_pk_bytes, agg_xonly, message, None
    )
    print(f"Other MuSig2 nonce generated: {other_pubnonce.hex()}")

    musig_aggnonce = musig_nonce_agg([tweaked_frost_aggnonce, other_pubnonce])
    print(f"MuSig2 aggregate nonce generated: {musig_aggnonce.hex()}")

    # Step 5: Signing
    print("\n5. Signing")
    print("-" * 30)
    musig_session_ctx = MusigSessionContext(
        musig_aggnonce,
        [frost_pk, other_pk_bytes],
        [],
        [],  # No tweaks
        message,
    )
    psig_frost_1 = nested_frost_sign(
        secnonce_0, frost_ser_secshares[0], 0, frost_session_ctx, musig_session_ctx
    )
    psig_frost_2 = nested_frost_sign(
        secnonce_2, frost_ser_secshares[2], 2, frost_session_ctx, musig_session_ctx
    )
    frost_psig = nested_frost_partial_sig_agg(
        [psig_frost_1, psig_frost_2], [0, 2], frost_session_ctx, musig_session_ctx
    )
    print("FROST signature generated successfully")
    print(f"FROST signature: {frost_psig.hex()}")

    other_psig = musig_sign(other_secnonce, other_secret.to_bytes(), musig_session_ctx)
    print("Other MuSig2 signature generated successfully")
    print(f"Other MuSig2 signature: {other_psig.hex()}")

    sig = musig_partial_sig_agg([frost_psig, other_psig], musig_session_ctx)
    print("MuSig2 signature generated successfully")
    print(f"MuSig2 signature: {sig.hex()}")
    print("=" * 50)
    print("Signature verification")
    print("-" * 30)

    if musig_schnorr_verify(message, agg_xonly, sig):
        print("✓ Signature verification PASSED")
    else:
        print("✗ Signature verification FAILED")


if __name__ == "__main__":
    demo()
