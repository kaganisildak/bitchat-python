#!/usr/bin/env python3.10

"""
Test script for Noise Identity Announcement binary encoding/decoding
"""

import time
import os


def encode_noise_identity_announcement_binary(
    peer_id: str,
    public_key: bytes,
    signing_public_key: bytes,
    nickname: str,
    timestamp: int,
    signature: bytes,
    previous_peer_id: str = None,
) -> bytes:
    """Encode noise identity announcement to binary format matching iOS"""
    data = bytearray()

    # Flags byte: bit 0 = hasPreviousPeerID
    flags = 0
    if previous_peer_id:
        flags |= 0x01
    data.append(flags)

    # PeerID as 8-byte hex string
    peer_data = bytes.fromhex(peer_id.ljust(16, "0")[:16])  # Pad to 8 bytes
    data.extend(peer_data)

    # PublicKey (length-prefixed)
    data.extend(len(public_key).to_bytes(4, "little"))
    data.extend(public_key)

    # SigningPublicKey (length-prefixed)
    data.extend(len(signing_public_key).to_bytes(4, "little"))
    data.extend(signing_public_key)

    # Nickname (length-prefixed string)
    nickname_bytes = nickname.encode("utf-8")
    data.extend(len(nickname_bytes).to_bytes(4, "little"))
    data.extend(nickname_bytes)

    # Timestamp (8 bytes)
    data.extend(timestamp.to_bytes(8, "little"))

    # PreviousPeerID if present
    if previous_peer_id:
        prev_data = bytes.fromhex(
            previous_peer_id.ljust(16, "0")[:16]
        )  # Pad to 8 bytes
        data.extend(prev_data)

    # Signature
    data.extend(signature)

    return bytes(data)


def parse_noise_identity_announcement_binary(data: bytes) -> dict:
    """Parse binary format noise identity announcement"""
    if len(data) < 20:  # Minimum size check
        raise ValueError("Data too short for identity announcement")

    offset = 0

    # Read flags byte
    flags = data[offset]
    offset += 1
    has_previous_peer_id = (flags & 0x01) != 0

    # Read peerID (8 bytes)
    if offset + 8 > len(data):
        raise ValueError("Insufficient data for peerID")
    peer_id_bytes = data[offset : offset + 8]
    peer_id = peer_id_bytes.hex()
    offset += 8

    # Read publicKey (length-prefixed)
    if offset + 4 > len(data):
        raise ValueError("Insufficient data for publicKey length")
    public_key_len = int.from_bytes(data[offset : offset + 4], "little")
    offset += 4

    if offset + public_key_len > len(data):
        raise ValueError("Insufficient data for publicKey")
    public_key = data[offset : offset + public_key_len]
    offset += public_key_len

    # Read signingPublicKey (length-prefixed)
    if offset + 4 > len(data):
        raise ValueError("Insufficient data for signingPublicKey length")
    signing_key_len = int.from_bytes(data[offset : offset + 4], "little")
    offset += 4

    if offset + signing_key_len > len(data):
        raise ValueError("Insufficient data for signingPublicKey")
    signing_public_key = data[offset : offset + signing_key_len]
    offset += signing_key_len

    # Read nickname (length-prefixed string)
    if offset + 4 > len(data):
        raise ValueError("Insufficient data for nickname length")
    nickname_len = int.from_bytes(data[offset : offset + 4], "little")
    offset += 4

    if offset + nickname_len > len(data):
        raise ValueError("Insufficient data for nickname")
    nickname = data[offset : offset + nickname_len].decode("utf-8")
    offset += nickname_len

    # Read timestamp (8 bytes)
    if offset + 8 > len(data):
        raise ValueError("Insufficient data for timestamp")
    timestamp = int.from_bytes(data[offset : offset + 8], "little")
    offset += 8

    # Read previousPeerID if present
    previous_peer_id = None
    if has_previous_peer_id:
        if offset + 8 > len(data):
            raise ValueError("Insufficient data for previousPeerID")
        prev_peer_bytes = data[offset : offset + 8]
        previous_peer_id = prev_peer_bytes.hex()
        offset += 8

    # Read signature (rest of data)
    if offset >= len(data):
        raise ValueError("No signature data")
    signature = data[offset:]

    return {
        "peerID": peer_id,
        "publicKey": public_key.hex(),
        "signingPublicKey": signing_public_key.hex(),
        "nickname": nickname,
        "timestamp": timestamp,
        "previousPeerID": previous_peer_id,
        "signature": signature.hex(),
    }


def test_identity_announcement():
    """Test encoding and decoding of identity announcements"""
    print("Testing Noise Identity Announcement binary format...")

    # Test data
    peer_id = "7e24c1f633915d33"
    public_key = os.urandom(32)  # 32-byte Curve25519 key
    signing_public_key = os.urandom(32)  # 32-byte Ed25519 key
    nickname = "testuser"
    timestamp = int(time.time() * 1000)  # milliseconds
    signature = os.urandom(64)  # 64-byte signature

    print(f"Original data:")
    print(f"  Peer ID: {peer_id}")
    print(f"  Public Key: {public_key.hex()[:32]}...")
    print(f"  Signing Key: {signing_public_key.hex()[:32]}...")
    print(f"  Nickname: {nickname}")
    print(f"  Timestamp: {timestamp}")
    print(f"  Signature: {signature.hex()[:32]}...")

    # Test encoding
    try:
        encoded = encode_noise_identity_announcement_binary(
            peer_id, public_key, signing_public_key, nickname, timestamp, signature
        )
        print(f"\n✓ Encoding successful: {len(encoded)} bytes")
        print(f"  First 32 bytes: {encoded[:32].hex()}")
    except Exception as e:
        print(f"✗ Encoding failed: {e}")
        return False

    # Test decoding
    try:
        decoded = parse_noise_identity_announcement_binary(encoded)
        print(f"\n✓ Decoding successful")
        print(f"  Decoded Peer ID: {decoded['peerID']}")
        print(f"  Decoded Nickname: {decoded['nickname']}")
        print(f"  Decoded Timestamp: {decoded['timestamp']}")
        print(f"  Decoded Public Key: {decoded['publicKey'][:32]}...")
        print(f"  Decoded Signing Key: {decoded['signingPublicKey'][:32]}...")
        print(f"  Decoded Signature: {decoded['signature'][:32]}...")
    except Exception as e:
        print(f"✗ Decoding failed: {e}")
        return False

    # Verify round-trip
    print(f"\nVerifying round-trip...")
    success = True

    if decoded["peerID"] != peer_id:
        print(f"✗ Peer ID mismatch: {decoded['peerID']} != {peer_id}")
        success = False

    if decoded["publicKey"] != public_key.hex():
        print(f"✗ Public key mismatch")
        success = False

    if decoded["signingPublicKey"] != signing_public_key.hex():
        print(f"✗ Signing public key mismatch")
        success = False

    if decoded["nickname"] != nickname:
        print(f"✗ Nickname mismatch: {decoded['nickname']} != {nickname}")
        success = False

    if decoded["timestamp"] != timestamp:
        print(f"✗ Timestamp mismatch: {decoded['timestamp']} != {timestamp}")
        success = False

    if decoded["signature"] != signature.hex():
        print(f"✗ Signature mismatch")
        success = False

    if decoded["previousPeerID"] is not None:
        print(f"✗ Previous peer ID should be None, got: {decoded['previousPeerID']}")
        success = False

    if success:
        print("✓ Round-trip verification successful!")

    return success


def test_with_previous_peer_id():
    """Test with previous peer ID set"""
    print("\nTesting with previous peer ID...")

    # Test data
    peer_id = "7e24c1f633915d33"
    previous_peer_id = "abcd1234567890ef"
    public_key = os.urandom(32)
    signing_public_key = os.urandom(32)
    nickname = "testuser2"
    timestamp = int(time.time() * 1000)
    signature = os.urandom(64)

    try:
        # Encode
        encoded = encode_noise_identity_announcement_binary(
            peer_id,
            public_key,
            signing_public_key,
            nickname,
            timestamp,
            signature,
            previous_peer_id,
        )
        print(f"✓ Encoding with previous peer ID successful: {len(encoded)} bytes")

        # Decode
        decoded = parse_noise_identity_announcement_binary(encoded)
        print(f"✓ Decoding successful")

        # Verify
        if decoded["previousPeerID"] != previous_peer_id:
            print(
                f"✗ Previous peer ID mismatch: {decoded['previousPeerID']} != {previous_peer_id}"
            )
            return False

        print(f"✓ Previous peer ID correctly preserved: {decoded['previousPeerID']}")
        return True

    except Exception as e:
        print(f"✗ Test with previous peer ID failed: {e}")
        return False


if __name__ == "__main__":
    print("=" * 60)
    print("Noise Identity Announcement Binary Format Test")
    print("=" * 60)

    success1 = test_identity_announcement()
    success2 = test_with_previous_peer_id()

    print("\n" + "=" * 60)
    if success1 and success2:
        print("🎉 All tests passed!")
    else:
        print("❌ Some tests failed!")
    print("=" * 60)
