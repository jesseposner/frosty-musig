"""
FROST + MuSig2 Nested Signing

WARNING: This is for demonstration purposes only, not for production use.
"""

import secrets
from hashlib import sha256

from frost_helper import G, Scalar, generate_frost_keys, get_session_values
from frost_helper import SessionContext as FrostSessionContext
from frost_helper import cpoint as frost_cpoint
from frost_helper import nonce_agg as frost_nonce_agg
from frost_helper import nonce_gen as frost_nonce_gen
from musig_helper import cbytes as musig_cbytes
from musig_helper import get_xonly_pk as musig_get_xonly_pk
from musig_helper import key_agg
from musig_helper import nonce_agg as musig_nonce_agg
from musig_helper import nonce_gen as musig_nonce_gen


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
    frost_session = FrostSessionContext(
        frost_aggnonce,
        signing_quorum,
        signing_pubshares,
        [],
        [],  # No tweaks
        message,
    )
    (_, _, _, b_frost, _, _) = get_session_values(frost_session)
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


if __name__ == "__main__":
    demo()
