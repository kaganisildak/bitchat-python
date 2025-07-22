"""
BitChat Protocol Implementation
Reverse-engineered from Swift implementation for protocol compatibility.
"""

import struct
import time
import uuid
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional, List, Dict, Any
import json

# Protocol Constants
PROTOCOL_VERSION = 1
HEADER_SIZE = 13
SENDER_ID_SIZE = 8
RECIPIENT_ID_SIZE = 8
SIGNATURE_SIZE = 64

# Special recipients
BROADCAST_RECIPIENT = b'\xFF' * 8

# Message padding block sizes
PADDING_BLOCK_SIZES = [256, 512, 1024, 2048]

class MessageType(IntEnum):
    """Message types matching Swift implementation"""
    ANNOUNCE = 0x01
    LEAVE = 0x03
    MESSAGE = 0x04
    FRAGMENT_START = 0x05
    FRAGMENT_CONTINUE = 0x06
    FRAGMENT_END = 0x07
    CHANNEL_ANNOUNCE = 0x08
    DELIVERY_ACK = 0x0A
    DELIVERY_STATUS_REQUEST = 0x0B
    READ_RECEIPT = 0x0C
    NOISE_HANDSHAKE_INIT = 0x10
    NOISE_HANDSHAKE_RESP = 0x11
    NOISE_ENCRYPTED = 0x12
    NOISE_IDENTITY_ANNOUNCE = 0x13
    CHANNEL_KEY_VERIFY_REQUEST = 0x14
    CHANNEL_KEY_VERIFY_RESPONSE = 0x15
    CHANNEL_PASSWORD_UPDATE = 0x16
    CHANNEL_METADATA = 0x17
    VERSION_HELLO = 0x20
    VERSION_ACK = 0x21

class PacketFlags(IntEnum):
    """Packet flags for binary protocol"""
    HAS_RECIPIENT = 0x01
    HAS_SIGNATURE = 0x02
    IS_COMPRESSED = 0x04

class MessageFlags(IntEnum):
    """Message flags for BitchatMessage binary format"""
    IS_RELAY = 0x01
    IS_PRIVATE = 0x02
    HAS_ORIGINAL_SENDER = 0x04
    HAS_RECIPIENT_NICKNAME = 0x08
    HAS_SENDER_PEER_ID = 0x10
    HAS_MENTIONS = 0x20
    HAS_CHANNEL = 0x40
    IS_ENCRYPTED = 0x80

@dataclass
class BitchatPacket:
    """
    Top-level BLE packet structure matching Swift implementation.
    
    Binary Protocol Format:
    Header (Fixed 13 bytes):
    - Version: 1 byte
    - Type: 1 byte  
    - TTL: 1 byte
    - Timestamp: 8 bytes (UInt64, big-endian)
    - Flags: 1 byte (bit 0: hasRecipient, bit 1: hasSignature, bit 2: isCompressed)
    - PayloadLength: 2 bytes (UInt16, big-endian)
    
    Variable sections:
    - SenderID: 8 bytes (fixed)
    - RecipientID: 8 bytes (if hasRecipient flag set)
    - Payload: Variable length
    - Signature: 64 bytes (if hasSignature flag set)
    """
    version: int
    message_type: int
    sender_id: bytes
    recipient_id: Optional[bytes]
    timestamp: int
    payload: bytes
    signature: Optional[bytes]
    ttl: int

    def __init__(self, message_type: int, sender_id: bytes, recipient_id: Optional[bytes] = None,
                 timestamp: Optional[int] = None, payload: bytes = b'', signature: Optional[bytes] = None,
                 ttl: int = 3):
        self.version = PROTOCOL_VERSION
        self.message_type = message_type
        self.sender_id = sender_id[:SENDER_ID_SIZE].ljust(SENDER_ID_SIZE, b'\x00')
        self.recipient_id = recipient_id[:RECIPIENT_ID_SIZE].ljust(RECIPIENT_ID_SIZE, b'\x00') if recipient_id else None
        self.timestamp = timestamp if timestamp is not None else int(time.time() * 1000)  # milliseconds
        self.payload = payload
        self.signature = signature
        self.ttl = ttl

    @classmethod
    def from_hex_sender(cls, message_type: int, sender_hex: str, **kwargs):
        """Create packet with hex string sender ID"""
        sender_bytes = bytes.fromhex(sender_hex.replace('-', ''))[:SENDER_ID_SIZE]
        sender_bytes = sender_bytes.ljust(SENDER_ID_SIZE, b'\x00')
        return cls(message_type=message_type, sender_id=sender_bytes, **kwargs)

    def to_binary(self, compression_util=None) -> bytes:
        """Encode packet to binary format with optional compression"""
        # Try compression if utility provided
        payload = self.payload
        original_payload_size = None
        is_compressed = False
        
        if compression_util and compression_util.should_compress(payload):
            compressed = compression_util.compress(payload)
            if compressed:
                original_payload_size = len(payload)
                payload = compressed
                is_compressed = True

        # Build header
        data = bytearray()
        data.append(self.version)
        data.append(self.message_type)
        data.append(self.ttl)
        
        # Timestamp (8 bytes, big-endian)
        data.extend(struct.pack('>Q', self.timestamp))
        
        # Flags
        flags = 0
        if self.recipient_id is not None:
            flags |= PacketFlags.HAS_RECIPIENT
        if self.signature is not None:
            flags |= PacketFlags.HAS_SIGNATURE
        if is_compressed:
            flags |= PacketFlags.IS_COMPRESSED
        data.append(flags)
        
        # Payload length (includes original size if compressed)
        payload_data_size = len(payload) + (2 if is_compressed else 0)
        data.extend(struct.pack('>H', payload_data_size))
        
        # Sender ID (exactly 8 bytes)
        data.extend(self.sender_id)
        
        # Recipient ID (if present)
        if self.recipient_id is not None:
            data.extend(self.recipient_id)
        
        # Payload (with original size prepended if compressed)
        if is_compressed and original_payload_size is not None:
            data.extend(struct.pack('>H', original_payload_size))
        data.extend(payload)
        
        # Signature (if present)
        if self.signature is not None:
            data.extend(self.signature[:SIGNATURE_SIZE])
        
        # Apply padding for traffic analysis resistance
        return self._apply_padding(bytes(data))

    @classmethod
    def from_binary(cls, data: bytes, compression_util=None) -> Optional['BitchatPacket']:
        """Decode binary data to BitchatPacket"""
        # Remove padding first
        data = cls._remove_padding(data)
        
        if len(data) < HEADER_SIZE + SENDER_ID_SIZE:
            return None
        
        offset = 0
        
        # Parse header
        version = data[offset]
        offset += 1
        
        if version != PROTOCOL_VERSION:
            return None
            
        message_type = data[offset]
        offset += 1
        
        ttl = data[offset]
        offset += 1
        
        # Timestamp (8 bytes, big-endian)
        timestamp = struct.unpack('>Q', data[offset:offset+8])[0]
        offset += 8
        
        # Flags
        flags = data[offset]
        offset += 1
        has_recipient = bool(flags & PacketFlags.HAS_RECIPIENT)
        has_signature = bool(flags & PacketFlags.HAS_SIGNATURE)
        is_compressed = bool(flags & PacketFlags.IS_COMPRESSED)
        
        # Payload length
        payload_length = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        
        # Calculate expected total size
        expected_size = HEADER_SIZE + SENDER_ID_SIZE + payload_length
        if has_recipient:
            expected_size += RECIPIENT_ID_SIZE
        if has_signature:
            expected_size += SIGNATURE_SIZE
        
        if len(data) < expected_size:
            return None
        
        # Sender ID
        sender_id = data[offset:offset+SENDER_ID_SIZE]
        offset += SENDER_ID_SIZE
        
        # Recipient ID
        recipient_id = None
        if has_recipient:
            recipient_id = data[offset:offset+RECIPIENT_ID_SIZE]
            offset += RECIPIENT_ID_SIZE
        
        # Payload
        if is_compressed:
            if payload_length < 2:
                return None
            original_size = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2
            compressed_payload = data[offset:offset+payload_length-2]
            offset += payload_length - 2
            
            if compression_util:
                payload = compression_util.decompress(compressed_payload, original_size)
                if payload is None:
                    return None
            else:
                payload = compressed_payload  # Can't decompress without utility
        else:
            payload = data[offset:offset+payload_length]
            offset += payload_length
        
        # Signature
        signature = None
        if has_signature:
            signature = data[offset:offset+SIGNATURE_SIZE]
        
        return cls(
            message_type=message_type,
            sender_id=sender_id,
            recipient_id=recipient_id,
            timestamp=timestamp,
            payload=payload,
            signature=signature,
            ttl=ttl
        )

    @staticmethod
    def _apply_padding(data: bytes) -> bytes:
        """Apply PKCS#7-style padding to reach optimal block size"""
        optimal_size = MessagePadding.optimal_block_size(len(data))
        return MessagePadding.pad(data, optimal_size)

    @staticmethod
    def _remove_padding(data: bytes) -> bytes:
        """Remove PKCS#7-style padding"""
        return MessagePadding.unpad(data)

    def get_sender_hex(self) -> str:
        """Get sender ID as hex string"""
        return self.sender_id.rstrip(b'\x00').hex()

    def get_recipient_hex(self) -> Optional[str]:
        """Get recipient ID as hex string"""
        if self.recipient_id is None:
            return None
        return self.recipient_id.rstrip(b'\x00').hex()

@dataclass 
class BitchatMessage:
    """
    User message structure with binary serialization.
    
    Message format:
    - Flags: 1 byte (various feature flags)
    - Timestamp: 8 bytes (milliseconds since epoch)
    - ID length: 1 byte + ID data
    - Sender length: 1 byte + Sender data  
    - Content length: 2 bytes + Content data
    - Optional fields based on flags
    """
    id: str
    sender: str
    content: str
    timestamp: float
    is_relay: bool = False
    original_sender: Optional[str] = None
    is_private: bool = False
    recipient_nickname: Optional[str] = None
    sender_peer_id: Optional[str] = None
    mentions: Optional[List[str]] = None
    channel: Optional[str] = None
    encrypted_content: Optional[bytes] = None
    is_encrypted: bool = False

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())

    def to_binary_payload(self) -> bytes:
        """Convert message to binary payload format"""
        data = bytearray()
        
        # Build flags
        flags = 0
        if self.is_relay:
            flags |= MessageFlags.IS_RELAY
        if self.is_private:
            flags |= MessageFlags.IS_PRIVATE
        if self.original_sender:
            flags |= MessageFlags.HAS_ORIGINAL_SENDER
        if self.recipient_nickname:
            flags |= MessageFlags.HAS_RECIPIENT_NICKNAME
        if self.sender_peer_id:
            flags |= MessageFlags.HAS_SENDER_PEER_ID
        if self.mentions:
            flags |= MessageFlags.HAS_MENTIONS
        if self.channel:
            flags |= MessageFlags.HAS_CHANNEL
        if self.is_encrypted:
            flags |= MessageFlags.IS_ENCRYPTED
        
        data.append(flags)
        
        # Timestamp (8 bytes, milliseconds)
        timestamp_ms = int(self.timestamp * 1000)
        data.extend(struct.pack('>Q', timestamp_ms))
        
        # ID
        id_data = self.id.encode('utf-8')[:255]
        data.append(len(id_data))
        data.extend(id_data)
        
        # Sender
        sender_data = self.sender.encode('utf-8')[:255]
        data.append(len(sender_data))
        data.extend(sender_data)
        
        # Content (or encrypted content)
        if self.is_encrypted and self.encrypted_content:
            content_data = self.encrypted_content[:65535]
        else:
            content_data = self.content.encode('utf-8')[:65535]
        
        data.extend(struct.pack('>H', len(content_data)))
        data.extend(content_data)
        
        # Optional fields
        if self.original_sender:
            orig_data = self.original_sender.encode('utf-8')[:255]
            data.append(len(orig_data))
            data.extend(orig_data)
        
        if self.recipient_nickname:
            recip_data = self.recipient_nickname.encode('utf-8')[:255]
            data.append(len(recip_data))
            data.extend(recip_data)
        
        if self.sender_peer_id:
            peer_data = self.sender_peer_id.encode('utf-8')[:255]
            data.append(len(peer_data))
            data.extend(peer_data)
        
        # Mentions array
        if self.mentions:
            data.append(min(len(self.mentions), 255))
            for mention in self.mentions[:255]:
                mention_data = mention.encode('utf-8')[:255]
                data.append(len(mention_data))
                data.extend(mention_data)
        
        # Channel
        if self.channel:
            channel_data = self.channel.encode('utf-8')[:255]
            data.append(len(channel_data))
            data.extend(channel_data)
        
        return bytes(data)

    @classmethod
    def from_binary_payload(cls, data: bytes) -> Optional['BitchatMessage']:
        """Parse binary payload to BitchatMessage"""
        if len(data) < 13:  # Minimum size
            return None
        
        offset = 0
        
        # Flags
        flags = data[offset]
        offset += 1
        
        is_relay = bool(flags & MessageFlags.IS_RELAY)
        is_private = bool(flags & MessageFlags.IS_PRIVATE)
        has_original_sender = bool(flags & MessageFlags.HAS_ORIGINAL_SENDER)
        has_recipient_nickname = bool(flags & MessageFlags.HAS_RECIPIENT_NICKNAME)
        has_sender_peer_id = bool(flags & MessageFlags.HAS_SENDER_PEER_ID)
        has_mentions = bool(flags & MessageFlags.HAS_MENTIONS)
        has_channel = bool(flags & MessageFlags.HAS_CHANNEL)
        is_encrypted = bool(flags & MessageFlags.IS_ENCRYPTED)
        
        # Timestamp
        if offset + 8 > len(data):
            return None
        timestamp_ms = struct.unpack('>Q', data[offset:offset+8])[0]
        timestamp = timestamp_ms / 1000.0
        offset += 8
        
        # ID
        if offset >= len(data):
            return None
        id_length = data[offset]
        offset += 1
        if offset + id_length > len(data):
            return None
        msg_id = data[offset:offset+id_length].decode('utf-8', errors='replace')
        offset += id_length
        
        # Sender
        if offset >= len(data):
            return None
        sender_length = data[offset]
        offset += 1
        if offset + sender_length > len(data):
            return None
        sender = data[offset:offset+sender_length].decode('utf-8', errors='replace')
        offset += sender_length
        
        # Content
        if offset + 2 > len(data):
            return None
        content_length = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        if offset + content_length > len(data):
            return None
        
        if is_encrypted:
            encrypted_content = data[offset:offset+content_length]
            content = ""  # Empty placeholder
        else:
            content = data[offset:offset+content_length].decode('utf-8', errors='replace')
            encrypted_content = None
        offset += content_length
        
        # Optional fields
        original_sender = None
        recipient_nickname = None
        sender_peer_id = None
        mentions = None
        channel = None
        
        if has_original_sender and offset < len(data):
            length = data[offset]
            offset += 1
            if offset + length <= len(data):
                original_sender = data[offset:offset+length].decode('utf-8', errors='replace')
                offset += length
        
        if has_recipient_nickname and offset < len(data):
            length = data[offset]
            offset += 1
            if offset + length <= len(data):
                recipient_nickname = data[offset:offset+length].decode('utf-8', errors='replace')
                offset += length
        
        if has_sender_peer_id and offset < len(data):
            length = data[offset]
            offset += 1
            if offset + length <= len(data):
                sender_peer_id = data[offset:offset+length].decode('utf-8', errors='replace')
                offset += length
        
        if has_mentions and offset < len(data):
            mention_count = data[offset]
            offset += 1
            mentions = []
            for _ in range(mention_count):
                if offset >= len(data):
                    break
                length = data[offset]
                offset += 1
                if offset + length <= len(data):
                    mention = data[offset:offset+length].decode('utf-8', errors='replace')
                    mentions.append(mention)
                    offset += length
        
        if has_channel and offset < len(data):
            length = data[offset]
            offset += 1
            if offset + length <= len(data):
                channel = data[offset:offset+length].decode('utf-8', errors='replace')
        
        return cls(
            id=msg_id,
            sender=sender,
            content=content,
            timestamp=timestamp,
            is_relay=is_relay,
            original_sender=original_sender,
            is_private=is_private,
            recipient_nickname=recipient_nickname,
            sender_peer_id=sender_peer_id,
            mentions=mentions,
            channel=channel,
            encrypted_content=encrypted_content,
            is_encrypted=is_encrypted
        )

class MessagePadding:
    """Privacy-preserving padding utilities"""
    
    @staticmethod
    def optimal_block_size(data_size: int) -> int:
        """Find optimal block size for data (accounts for encryption overhead)"""
        total_size = data_size + 16  # AES-GCM tag overhead
        
        for block_size in PADDING_BLOCK_SIZES:
            if total_size <= block_size:
                return block_size
        
        # For very large messages, use original size
        return data_size

    @staticmethod
    def pad(data: bytes, target_size: int) -> bytes:
        """Add PKCS#7-style padding to reach target size"""
        if len(data) >= target_size:
            return data
        
        padding_needed = target_size - len(data)
        
        # PKCS#7 only supports padding up to 255 bytes
        if padding_needed > 255:
            return data
        
        # Generate random padding bytes + length byte
        import secrets
        random_bytes = secrets.token_bytes(padding_needed - 1)
        return data + random_bytes + bytes([padding_needed])

    @staticmethod
    def unpad(data: bytes) -> bytes:
        """Remove PKCS#7-style padding"""
        if not data:
            return data
        
        # Last byte tells us padding length
        padding_length = data[-1]
        
        if padding_length == 0 or padding_length > len(data):
            return data  # Invalid padding
        
        return data[:-padding_length]

@dataclass
class VersionHello:
    """Version negotiation hello message"""
    supported_versions: List[int]
    preferred_version: int
    client_version: str
    platform: str
    capabilities: Optional[List[str]] = None

    def encode(self) -> bytes:
        """Encode to JSON bytes"""
        data = {
            'supportedVersions': self.supported_versions,
            'preferredVersion': self.preferred_version,
            'clientVersion': self.client_version,
            'platform': self.platform
        }
        if self.capabilities:
            data['capabilities'] = self.capabilities
        return json.dumps(data).encode('utf-8')

    @classmethod
    def decode(cls, data: bytes) -> Optional['VersionHello']:
        """Decode from JSON bytes"""
        try:
            obj = json.loads(data.decode('utf-8'))
            return cls(
                supported_versions=obj['supportedVersions'],
                preferred_version=obj['preferredVersion'],
                client_version=obj['clientVersion'],
                platform=obj['platform'],
                capabilities=obj.get('capabilities')
            )
        except (json.JSONDecodeError, KeyError, UnicodeDecodeError):
            return None

@dataclass
class VersionAck:
    """Version negotiation acknowledgment"""
    agreed_version: int
    client_version: str
    platform: str

    def encode(self) -> bytes:
        """Encode to JSON bytes"""
        data = {
            'agreedVersion': self.agreed_version,
            'clientVersion': self.client_version,
            'platform': self.platform
        }
        return json.dumps(data).encode('utf-8')

    @classmethod
    def decode(cls, data: bytes) -> Optional['VersionAck']:
        """Decode from JSON bytes"""
        try:
            obj = json.loads(data.decode('utf-8'))
            return cls(
                agreed_version=obj['agreedVersion'],
                client_version=obj['clientVersion'],
                platform=obj['platform']
            )
        except (json.JSONDecodeError, KeyError, UnicodeDecodeError):
            return None

# BLE Service constants
BLE_SERVICE_UUID = "F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C"
BLE_CHARACTERISTIC_UUID = "A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D"

# Protocol version constants
SUPPORTED_VERSIONS = [1]
CURRENT_VERSION = 1 