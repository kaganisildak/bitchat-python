#!/usr/bin/env python3
import asyncio
import sys
import os
import time
import json
import uuid
import struct
import hashlib
import random
from datetime import datetime
from typing import Optional, Dict, List, Tuple, Set, Union
from dataclasses import dataclass, field
from enum import IntEnum
from collections import defaultdict
import logging
import base64

from bleak import BleakClient, BleakScanner, BleakGATTCharacteristic
from bleak.backends.device import BLEDevice
import aioconsole
from pybloom_live import BloomFilter

from encryption import EncryptionService, NoiseError
from compression import compress_if_beneficial, decompress
from fragmentation import Fragment, FragmentType, fragment_payload
from terminal_ux import ChatContext, ChatMode, Public, Channel, PrivateDM, format_message_display, print_help, clear_screen
from persistence import AppState, load_state, save_state, encrypt_password, decrypt_password

# Version
VERSION = "v1.1.0"

# UUIDs
BITCHAT_SERVICE_UUID = "f47b5e2d-4a9e-4c5a-9b3f-8e1d2c3a4b5c"
BITCHAT_CHARACTERISTIC_UUID = "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d"

# Cover traffic prefix used by iOS
COVER_TRAFFIC_PREFIX = "☂DUMMY☂"

# Packet header flags
FLAG_HAS_RECIPIENT = 0x01
FLAG_HAS_SIGNATURE = 0x02
FLAG_IS_COMPRESSED = 0x04

# Message payload flags
MSG_FLAG_IS_RELAY = 0x01
MSG_FLAG_IS_PRIVATE = 0x02
MSG_FLAG_HAS_ORIGINAL_SENDER = 0x04
MSG_FLAG_HAS_RECIPIENT_NICKNAME = 0x08
MSG_FLAG_HAS_SENDER_PEER_ID = 0x10
MSG_FLAG_HAS_MENTIONS = 0x20
MSG_FLAG_HAS_CHANNEL = 0x40
MSG_FLAG_IS_ENCRYPTED = 0x80

SIGNATURE_SIZE = 64
BROADCAST_RECIPIENT = b'\xFF' * 8

# Debug levels
class DebugLevel(IntEnum):
    CLEAN = 0
    BASIC = 1
    FULL = 2

DEBUG_LEVEL = DebugLevel.CLEAN

def debug_println(*args, **kwargs):
    if DEBUG_LEVEL >= DebugLevel.BASIC:
        try:
            print(*args, **kwargs)
        except BlockingIOError:
            # Silently ignore blocking errors in debug output
            pass

def debug_full_println(*args, **kwargs):
    if DEBUG_LEVEL >= DebugLevel.FULL:
        try:
            print(*args, **kwargs)
        except BlockingIOError:
            # Silently ignore blocking errors in debug output
            pass

# Message types
class MessageType(IntEnum):
    ANNOUNCE = 0x01
    KEY_EXCHANGE = 0x02
    LEAVE = 0x03
    MESSAGE = 0x04
    FRAGMENT_START = 0x05
    FRAGMENT_CONTINUE = 0x06
    FRAGMENT_END = 0x07
    CHANNEL_ANNOUNCE = 0x08
    CHANNEL_RETENTION = 0x09
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

@dataclass
class Peer:
    nickname: Optional[str] = None

@dataclass
class BitchatPacket:
    msg_type: MessageType
    sender_id: bytes
    sender_id_str: str
    recipient_id: Optional[bytes]
    recipient_id_str: Optional[str]
    payload: bytes
    ttl: int

@dataclass
class BitchatMessage:
    id: str
    content: str
    channel: Optional[str]
    is_encrypted: bool
    encrypted_content: Optional[bytes]

@dataclass
class DeliveryAck:
    original_message_id: str
    ack_id: str
    recipient_id: str
    recipient_nickname: str
    timestamp: int
    hop_count: int

class DeliveryTracker:
    def __init__(self):
        self.pending_messages: Dict[str, Tuple[str, float, bool]] = {}
        self.sent_acks: Set[str] = set()
    
    def track_message(self, message_id: str, content: str, is_private: bool):
        self.pending_messages[message_id] = (content, time.time(), is_private)
    
    def mark_delivered(self, message_id: str) -> bool:
        return self.pending_messages.pop(message_id, None) is not None
    
    def should_send_ack(self, ack_id: str) -> bool:
        if ack_id in self.sent_acks:
            return False
        self.sent_acks.add(ack_id)
        return True

class FragmentCollector:
    def __init__(self):
        self.fragments: Dict[str, Dict[int, bytes]] = {}
        self.metadata: Dict[str, Tuple[int, int, str]] = {}
    
    def add_fragment(self, fragment_id: bytes, index: int, total: int, 
                    original_type: int, data: bytes, sender_id: str) -> Optional[Tuple[bytes, str]]:
        fragment_id_hex = fragment_id.hex()
        
        debug_full_println(f"[COLLECTOR] Adding fragment {index + 1}/{total} for ID {fragment_id_hex[:8]}")
        
        if fragment_id_hex not in self.fragments:
            debug_full_println(f"[COLLECTOR] Creating new fragment collection for ID {fragment_id_hex[:8]}")
            self.fragments[fragment_id_hex] = {}
            self.metadata[fragment_id_hex] = (total, original_type, sender_id)
        
        fragment_map = self.fragments[fragment_id_hex]
        fragment_map[index] = data
        debug_full_println(f"[COLLECTOR] Fragment {index + 1} stored. Have {len(fragment_map)}/{total} fragments")
        
        if len(fragment_map) == total:
            debug_full_println("[COLLECTOR] ✓ All fragments received! Reassembling...")
            
            complete_data = bytearray()
            for i in range(total):
                if i in fragment_map:
                    debug_full_println(f"[COLLECTOR] Appending fragment {i + 1} ({len(fragment_map[i])} bytes)")
                    complete_data.extend(fragment_map[i])
                else:
                    debug_full_println(f"[COLLECTOR] ✗ Missing fragment {i + 1}")
                    return None
            
            debug_full_println(f"[COLLECTOR] ✓ Reassembly complete: {len(complete_data)} bytes total")
            
            sender = self.metadata.get(fragment_id_hex, (0, 0, "Unknown"))[2]
            
            del self.fragments[fragment_id_hex]
            del self.metadata[fragment_id_hex]
            
            return (bytes(complete_data), sender)
        
        return None

class BitchatClient:
    def __init__(self):
        self.my_peer_id = os.urandom(8).hex()
        self.nickname = "my-python-client"
        self.peers: Dict[str, Peer] = {}
        self.bloom = BloomFilter(capacity=500, error_rate=0.01)
        self.processed_messages: Set[str] = set()  # Backup for message IDs
        self.fragment_collector = FragmentCollector()
        self.delivery_tracker = DeliveryTracker()
        self.chat_context = ChatContext()
        self.channel_keys: Dict[str, bytes] = {}
        self.app_state = AppState()
        self.blocked_peers: Set[str] = set()
        self.channel_creators: Dict[str, str] = {}
        self.password_protected_channels: Set[str] = set()
        self.channel_key_commitments: Dict[str, str] = {}
        self.discovered_channels: Set[str] = set()
        self.encryption_service = EncryptionService()
        self.client: Optional[BleakClient] = None
        self.characteristic: Optional[BleakGATTCharacteristic] = None
        self.running = True
        self.background_scanner_task = None  # Track background scanner task
        self.disconnection_callback_registered = False
        
        # Handshake timing tracking (like Swift implementation)
        self.handshake_attempt_times: Dict[str, float] = {}
        self.handshake_timeout = 5.0  # 5 seconds before retrying, matching Swift
        
        # Pending private messages waiting for handshake completion
        self.pending_private_messages: Dict[str, List[Tuple[str, str, str]]] = {}  # peer_id -> [(content, nickname, message_id)]
        
        # Setup encryption service callbacks for better handshake handling
        self.encryption_service.on_peer_authenticated = self._on_peer_authenticated
        self.encryption_service.on_handshake_required = self._on_handshake_required
    
    def _on_peer_authenticated(self, peer_id: str, fingerprint: str):
        """Callback when a peer is authenticated via Noise protocol"""
        debug_println(f"[NOISE] Peer {peer_id} authenticated with fingerprint: {fingerprint[:16]}...")
        
        # Send any pending private messages for this peer
        asyncio.create_task(self.send_pending_private_messages(peer_id))
        
    def _on_handshake_required(self, peer_id: str):
        """Callback when handshake is required for a peer"""
        debug_println(f"[NOISE] Handshake required for peer {peer_id}")
        # The handshake will be initiated when trying to send private messages
    
    async def send_pending_private_messages(self, peer_id: str):
        """Send all pending private messages for a peer after handshake completes"""
        if peer_id not in self.pending_private_messages:
            return
        
        pending_messages = self.pending_private_messages.pop(peer_id, [])
        if not pending_messages:
            return
        
        debug_println(f"[NOISE] Sending {len(pending_messages)} pending messages to {peer_id}")
        
        for content, nickname, message_id in pending_messages:
            try:
                # Add longer delay before sending to allow BLE queue to clear
                await asyncio.sleep(0.3)
                # Call the actual send function with established session
                await self.send_private_message(content, peer_id, nickname, message_id)
                # Small delay between messages
                await asyncio.sleep(0.2)
            except Exception as e:
                debug_println(f"[NOISE] Failed to send pending message to {peer_id}: {e}")
                # Re-queue the message if it's a temporary error
                if "blocking" in str(e).lower():
                    debug_println(f"[NOISE] Re-queuing message due to BLE congestion")
                    if peer_id not in self.pending_private_messages:
                        self.pending_private_messages[peer_id] = []
                    self.pending_private_messages[peer_id].append((content, nickname, message_id))
                    # Don't retry immediately, let it retry later
                    break
        
    async def find_device(self) -> Optional[BLEDevice]:
        """Scan for BitChat service"""
        debug_println("[1] Scanning for bitchat service...")
        
        devices = await BleakScanner.discover(
            timeout=5.0,
            service_uuids=[BITCHAT_SERVICE_UUID]
        )
        
        for device in devices:
            debug_full_println(f"Found device: {device.name} - {device.address}")
            return device
        
        return None
    
    def handle_disconnect(self, client: BleakClient):
        """Handle disconnection from peer"""
        print(f"\r\033[K\033[91m✗ Disconnected from BitChat network\033[0m")
        print("\033[90m» Scanning for other devices...\033[0m")
        print("> ", end='', flush=True)
        
        # Clear connection state
        self.client = None
        self.characteristic = None
        self.peers.clear()  # Clear peer list since we're disconnected
        self.chat_context.active_dms.clear()  # Clear DM list
        
        # Clear encryption sessions (but keep our own identity)
        self.encryption_service.sessions.clear()
        self.encryption_service.handshake_states.clear()
        
        # Clear pending private messages
        self.pending_private_messages.clear()
        
        # If in a DM, switch to public
        if isinstance(self.chat_context.current_mode, PrivateDM):
            self.chat_context.switch_to_public()
        
        # Restart background scanner if not already running
        if not self.background_scanner_task or self.background_scanner_task.done():
            self.background_scanner_task = asyncio.create_task(self.background_scanner())
    
    async def connect(self):
        """Connect to BitChat service"""
        print("\033[90m» Scanning for bitchat service...\033[0m")
        
        scan_attempts = 0
        max_initial_attempts = 10  # Try for ~10 seconds initially
        
        device = None
        while not device and self.running:
            device = await self.find_device()
            if not device:
                scan_attempts += 1
                if scan_attempts == max_initial_attempts:
                    print("\033[93m» No other BitChat devices found yet.\033[0m")
                    print("\033[90m» This might be because:\033[0m")
                    print("\033[90m  • You're the first one here (that's okay!)\033[0m")
                    print("\033[90m  • Other devices are out of Bluetooth range\033[0m")
                    print("\033[90m  • The iOS/Android app needs to be open\033[0m")
                    print("\033[90m» Continuing to scan in the background...\033[0m")
                    print("\033[90m» You can start using commands while waiting.\033[0m")
                    # Return True to continue without connection
                    return True
                await asyncio.sleep(1)
        
        if not self.running:
            return False
        
        print("\033[90m» Found bitchat service! Connecting...\033[0m")
        debug_println("[1] Match Found! Connecting...")
        
        try:
            self.client = BleakClient(device.address, disconnected_callback=self.handle_disconnect)
            await self.client.connect()
            
            # Find characteristic
            services = self.client.services
            if not services:
                raise Exception("No services found on device")
                
            for service in services:
                for char in service.characteristics:
                    if char.uuid.lower() == BITCHAT_CHARACTERISTIC_UUID.lower():
                        self.characteristic = char
                        debug_println(f"[2] Found characteristic: {char.uuid}")
                        break
                if self.characteristic:
                    break
            
            if not self.characteristic:
                raise Exception("Characteristic not found")
            
            # Subscribe to notifications
            await self.client.start_notify(self.characteristic, self.notification_handler)
            
            debug_println("[2] Connection established.")
            return True
            
        except Exception as e:
            print(f"\n\033[91m❌ Connection failed\033[0m")
            print(f"\033[90mReason: {e}\033[0m")
            print("\033[90mPlease check:\033[0m")
            print("\033[90m  • Bluetooth is enabled\033[0m")
            print("\033[90m  • The other device is running BitChat\033[0m")
            print("\033[90m  • You're within range\033[0m")
            print("\n\033[90mTry running the command again.\033[0m")
            return False
    
    async def handshake(self):
        """Perform initial handshake"""
        debug_println("[3] Performing handshake...")
        
        # Load persisted state
        self.app_state = load_state()
        if self.app_state.nickname:
            self.nickname = self.app_state.nickname
        
        # If we have a connection, send Noise identity announce and regular announce
        if self.client and self.characteristic:
            # Send Noise identity announcement first
            try:
                # Create a proper timestamp that matches iOS (milliseconds since epoch)
                timestamp_ms = int(time.time() * 1000)
                public_key_bytes = self.encryption_service.get_public_key()
                signing_public_key_bytes = self.encryption_service.get_signing_public_key_bytes()
                
                # Create binding data for signature (matching iOS)
                # iOS uses: peerID + publicKey + timestamp (as string)
                timestamp_data = str(timestamp_ms).encode('utf-8')
                binding_data = self.my_peer_id.encode('utf-8') + public_key_bytes + timestamp_data
                signature = self.encryption_service.sign_data(binding_data)
                
                # Encode to binary format
                identity_payload = self.encode_noise_identity_announcement_binary(
                    self.my_peer_id, public_key_bytes, signing_public_key_bytes,
                    self.nickname, timestamp_ms, signature
                )
                
                identity_packet = create_bitchat_packet_with_signature(
                    self.my_peer_id, MessageType.NOISE_IDENTITY_ANNOUNCE, identity_payload, signature
                )
                await self.send_packet(identity_packet)
                debug_println("[3] Sent Noise identity announcement (binary format)")
            except Exception as e:
                debug_println(f"[3] Failed to send identity announcement: {e}")
                import traceback
                debug_println(f"[3] Traceback: {traceback.format_exc()}")
                # Fallback to old key exchange
                handshake_message = self.encryption_service.initiate_handshake(self.my_peer_id)
                handshake_packet = create_bitchat_packet(
                    self.my_peer_id, MessageType.KEY_EXCHANGE, handshake_message
                )
                await self.send_packet(handshake_packet)
            
            # Wait a bit between packets
            await asyncio.sleep(0.5)
            
            # Send announce
            announce_packet = create_bitchat_packet(
                self.my_peer_id, MessageType.ANNOUNCE, self.nickname.encode()
            )
            await self.send_packet(announce_packet)
            
            debug_println("[3] Handshake sent. You can now chat.")
        else:
            debug_println("[3] No connection yet. Skipping handshake.")
            print("\033[90m» Running in offline mode. Waiting for peers...\033[0m")
        
        if self.app_state.nickname:
            print(f"\033[90m» Using saved nickname: {self.nickname}\033[0m")
        print("\033[90m» Type /status to see connection info\033[0m")
        
        # Restore state
        self.blocked_peers = self.app_state.blocked_peers
        self.channel_creators = self.app_state.channel_creators
        self.password_protected_channels = self.app_state.password_protected_channels
        self.channel_key_commitments = self.app_state.channel_key_commitments
        
        # Restore channel keys from saved passwords
        if self.app_state.identity_key:
            for channel, encrypted_password in self.app_state.encrypted_channel_passwords.items():
                try:
                    password = decrypt_password(encrypted_password, self.app_state.identity_key)
                    key = EncryptionService.derive_channel_key(password, channel)
                    self.channel_keys[channel] = key
                    debug_println(f"[CHANNEL] Restored key for password-protected channel: {channel}")
                except Exception as e:
                    debug_println(f"[CHANNEL] Failed to restore key for {channel}: {e}")
    
    async def send_packet(self, packet: bytes):
        """Send packet, with fragmentation if needed"""
        debug_full_println(f"[RAW SEND] {packet.hex()}")
        if not self.client or not self.characteristic:
            debug_println("[!] No connection available. Message queued.")
            # In a real implementation, we might queue messages here
            return
        
        # Check if still connected before sending
        if not self.client.is_connected:
            debug_println("[!] Connection lost. Cannot send packet.")
            # Trigger disconnection handling if not already done
            if self.client:
                self.handle_disconnect(self.client)
            return
            
        if should_fragment(packet):
            await self.send_packet_with_fragmentation(packet)
        else:
            write_with_response = len(packet) > 512
            try:
                # Add small delay to prevent blocking errors
                await asyncio.sleep(0.01)
                await self.client.write_gatt_char(
                    self.characteristic, 
                    packet, 
                    response=write_with_response
                )
            except Exception as e:
                # Check if this is a connection error
                if "not connected" in str(e).lower():
                    debug_println("[!] Lost connection while sending")
                    if self.client:
                        self.handle_disconnect(self.client)
                    return
                
                # Handle blocking errors by retrying without response
                if "could not complete without blocking" in str(e) or write_with_response:
                    try:
                        debug_println(f"[!] Write blocked, retrying without response after delay")
                        await asyncio.sleep(0.1)  # Longer delay for retry
                        await self.client.write_gatt_char(
                            self.characteristic, 
                            packet, 
                            response=False
                        )
                        debug_println(f"[!] Retry successful")
                    except Exception as e2:
                        if "not connected" in str(e2).lower():
                            debug_println("[!] Lost connection while sending")
                            if self.client:
                                self.handle_disconnect(self.client)
                        elif "could not complete without blocking" in str(e2):
                            debug_println(f"[!] Write still blocked after retry, dropping packet")
                            # Don't raise, just log and continue
                        else:
                            raise e2
                else:
                    raise e
    
    async def send_packet_with_fragmentation(self, packet: bytes):
        """Fragment and send large packets"""
        if not self.client or not self.characteristic:
            debug_println("[!] No connection available. Cannot send fragmented message.")
            return
        
        # Check if still connected
        if not self.client.is_connected:
            debug_println("[!] Connection lost. Cannot send fragmented packet.")
            if self.client:
                self.handle_disconnect(self.client)
            return
            
        debug_println(f"[FRAG] Original packet size: {len(packet)} bytes")
        
        fragment_size = 150  # Conservative size for iOS BLE
        chunks = [packet[i:i+fragment_size] for i in range(0, len(packet), fragment_size)]
        total_fragments = len(chunks)
        
        fragment_id = os.urandom(8)
        debug_println(f"[FRAG] Fragment ID: {fragment_id.hex()}")
        debug_println(f"[FRAG] Total fragments: {total_fragments}")
        
        for index, chunk in enumerate(chunks):
            if index == 0:
                fragment_type = MessageType.FRAGMENT_START
            elif index == len(chunks) - 1:
                fragment_type = MessageType.FRAGMENT_END
            else:
                fragment_type = MessageType.FRAGMENT_CONTINUE
            
            # Create fragment payload
            fragment_payload = bytearray()
            fragment_payload.extend(fragment_id)
            fragment_payload.extend(struct.pack('>H', index))
            fragment_payload.extend(struct.pack('>H', total_fragments))
            fragment_payload.append(MessageType.MESSAGE.value)
            fragment_payload.extend(chunk)
            
            fragment_packet = create_bitchat_packet(
                self.my_peer_id,
                fragment_type,
                bytes(fragment_payload)
            )
            
            try:
                await self.client.write_gatt_char(
                    self.characteristic,
                    fragment_packet,
                    response=False
                )
                
                debug_println(f"[FRAG] ✓ Fragment {index + 1}/{total_fragments} sent")
                
                if index < len(chunks) - 1:
                    await asyncio.sleep(0.02)  # 20ms delay
            except Exception as e:
                if "not connected" in str(e).lower():
                    debug_println(f"[FRAG] Connection lost while sending fragment {index + 1}")
                    if self.client:
                        self.handle_disconnect(self.client)
                    return
                else:
                    raise e
    
    async def notification_handler(self, sender: BleakGATTCharacteristic, data: bytes):
        """Handle incoming BLE notifications"""
        try:
            # Enhanced hex logging to match iOS format
            hex_string = ' '.join(f'{b:02X}' for b in data)
            debug_full_println(f"[RAW RECV] Received {len(data)} bytes")
            debug_full_println(f"[RAW RECV] {hex_string}")
        except BlockingIOError:
            # If even debug printing fails due to blocking, just silently continue
            pass
            
        try:
            packet = parse_bitchat_packet(data)
            
            # Ignore our own messages (they are already displayed when sent)
            if packet.sender_id_str == self.my_peer_id:
                return
            
            await self.handle_packet(packet, data)
            
        except Exception as e:
            try:
                debug_full_println(f"[ERROR] Failed to parse packet: {e}")
            except BlockingIOError:
                # Silently ignore blocking errors
                pass
    
    async def handle_packet(self, packet: BitchatPacket, raw_data: bytes):
        """Handle incoming packet"""
        if packet.msg_type == MessageType.ANNOUNCE:
            await self.handle_announce(packet)
        elif packet.msg_type == MessageType.MESSAGE:
            await self.handle_message(packet, raw_data)
        elif packet.msg_type in [MessageType.FRAGMENT_START, MessageType.FRAGMENT_CONTINUE, MessageType.FRAGMENT_END]:
            await self.handle_fragment(packet, raw_data)
        elif packet.msg_type == MessageType.KEY_EXCHANGE:
            await self.handle_key_exchange(packet)
        elif packet.msg_type == MessageType.NOISE_HANDSHAKE_INIT:
            await self.handle_noise_handshake_init(packet)
        elif packet.msg_type == MessageType.NOISE_HANDSHAKE_RESP:
            await self.handle_noise_handshake_resp(packet)
        elif packet.msg_type == MessageType.NOISE_ENCRYPTED:
            await self.handle_noise_encrypted(packet, raw_data)
        elif packet.msg_type == MessageType.LEAVE:
            await self.handle_leave(packet)
        elif packet.msg_type == MessageType.CHANNEL_ANNOUNCE:
            await self.handle_channel_announce(packet)
        elif packet.msg_type == MessageType.NOISE_IDENTITY_ANNOUNCE:
            await self.handle_noise_identity_announce(packet)
    
    async def handle_announce(self, packet: BitchatPacket):
        """Handle peer announcement"""
        peer_nickname = packet.payload.decode('utf-8', errors='ignore').strip()
        is_new_peer = packet.sender_id_str not in self.peers
        
        if packet.sender_id_str not in self.peers:
            self.peers[packet.sender_id_str] = Peer()
        
        self.peers[packet.sender_id_str].nickname = peer_nickname
        
        if is_new_peer:
            print(f"\r\033[K\033[33m{peer_nickname} connected\033[0m\n> ", end='', flush=True)
            debug_println(f"[<-- RECV] Announce: Peer {packet.sender_id_str} is now known as '{peer_nickname}'")
            
            # Apply tie-breaker logic like iOS client
            if self.my_peer_id < packet.sender_id_str:
                # We have lower ID, initiate handshake
                debug_println(f"[CRYPTO] Initiating Noise handshake with new peer {packet.sender_id_str} (tie-breaker: we have lower ID)")
                try:
                    handshake_message = self.encryption_service.initiate_handshake(packet.sender_id_str)
                    handshake_packet = create_bitchat_packet_with_recipient(
                        self.my_peer_id, packet.sender_id_str, MessageType.NOISE_HANDSHAKE_INIT, handshake_message, None
                    )
                    # Set TTL to 3 like iOS
                    handshake_data = bytearray(handshake_packet)
                    handshake_data[2] = 3
                    handshake_packet = bytes(handshake_data)
                    await self.send_packet(handshake_packet)
                    debug_println(f"[NOISE] Sent handshake init to {packet.sender_id_str}, payload size: {len(handshake_message)}")
                except Exception as e:
                    debug_println(f"[CRYPTO] Failed to initiate handshake: {e}")
                    # Fallback to old key exchange
                    key_exchange_payload = self.encryption_service.get_combined_public_key_data()
                    key_exchange_packet = create_bitchat_packet(
                        self.my_peer_id, MessageType.KEY_EXCHANGE, key_exchange_payload
                    )
                    await self.send_packet(key_exchange_packet)
            else:
                # We have higher ID, send targeted identity announce to prompt them to initiate
                debug_println(f"[CRYPTO] Sending targeted identity announce to {packet.sender_id_str} (tie-breaker: they have lower ID)")
                try:
                    timestamp_ms = int(time.time() * 1000)
                    public_key_bytes = self.encryption_service.get_public_key()
                    signing_public_key_bytes = self.encryption_service.get_signing_public_key_bytes()
                    
                    # Create binding data for signature
                    timestamp_data = str(timestamp_ms).encode('utf-8')
                    binding_data = self.my_peer_id.encode('utf-8') + public_key_bytes + timestamp_data
                    signature = self.encryption_service.sign_data(binding_data)
                    
                    # Encode to binary format
                    identity_payload = self.encode_noise_identity_announcement_binary(
                        self.my_peer_id, public_key_bytes, signing_public_key_bytes,
                        self.nickname, timestamp_ms, signature
                    )
                    
                    identity_packet = create_bitchat_packet_with_recipient(
                        self.my_peer_id, packet.sender_id_str, MessageType.NOISE_IDENTITY_ANNOUNCE, 
                        identity_payload, signature
                    )
                    await self.send_packet(identity_packet)
                except Exception as e:
                    debug_println(f"[CRYPTO] Failed to send targeted identity announce: {e}")
    
    async def handle_message(self, packet: BitchatPacket, raw_data: bytes):
        """Handle chat message"""
        # Check if sender is blocked
        fingerprint = self.encryption_service.get_peer_fingerprint(packet.sender_id_str)
        if fingerprint and fingerprint in self.blocked_peers:
            debug_println(f"[BLOCKED] Ignoring message from blocked peer: {packet.sender_id_str}")
            return
        
        # Check if message is for us
        is_broadcast = packet.recipient_id == BROADCAST_RECIPIENT if packet.recipient_id else True
        is_for_us = is_broadcast or (packet.recipient_id_str == self.my_peer_id)
        
        if not is_for_us:
            # Relay if TTL > 1
            if packet.ttl > 1:
                await asyncio.sleep(random.uniform(0.01, 0.05))
                relay_data = bytearray(raw_data)
                relay_data[2] = packet.ttl - 1
                await self.send_packet(bytes(relay_data))
            return
        is_private_message = not is_broadcast and is_for_us
        decrypted_payload = None
        if is_private_message:
            try:
                decrypted_payload = self.encryption_service.decrypt_from_peer(packet.sender_id_str, packet.payload)
                debug_println("[PRIVATE] Successfully decrypted private message!")
            except NoiseError:
                debug_println("[PRIVATE] Failed to decrypt private message")
                return
        # Parse message first to check if it's actually a private message
        try:
            if is_private_message and decrypted_payload:
                unpadded = unpad_message(decrypted_payload)
                message = parse_bitchat_message_payload(unpadded)
            else:
                message = parse_bitchat_message_payload(packet.payload)
            # Check for duplicates using both bloom filter and set
            if message.id not in self.processed_messages:
                # Add to bloom filter and set
                self.bloom.add(message.id)
                self.processed_messages.add(message.id)
                
                # Display the message
                await self.display_message(message, packet, is_private_message)
                
                # Send ACK if needed
                if should_send_ack(is_private_message, message.channel, None, self.nickname, len(self.peers)):
                    await self.send_delivery_ack(message.id, packet.sender_id_str, is_private_message)
                
                # Relay if TTL > 1
                if packet.ttl > 1:
                    await asyncio.sleep(random.uniform(0.01, 0.05))
                    relay_data = bytearray(raw_data)
                    relay_data[2] = packet.ttl - 1
                    await self.send_packet(bytes(relay_data))
            else:
                debug_println(f"[DUPLICATE] Ignoring duplicate message: {message.id}")
                    
        except Exception as e:
            debug_full_println(f"[ERROR] Failed to parse message: {e}")
    
    async def display_message(self, message: BitchatMessage, packet: BitchatPacket, is_private: bool):
        """Display a message in the terminal"""
        sender_nick = self.peers.get(packet.sender_id_str, Peer()).nickname or packet.sender_id_str
        
        # Track discovered channels
        if message.channel:
            self.discovered_channels.add(message.channel)
            if message.is_encrypted:
                self.password_protected_channels.add(message.channel)
        
        # Decrypt channel messages if we have the key
        display_content = message.content
        if message.is_encrypted and message.channel and message.channel in self.channel_keys:
            try:
                creator_fingerprint = self.channel_creators.get(message.channel, '')
                decrypted = self.encryption_service.decrypt_from_channel(
                    message.encrypted_content,
                    message.channel,
                    self.channel_keys[message.channel],
                    creator_fingerprint
                )
                display_content = decrypted
            except:
                display_content = "[Encrypted message - decryption failed]"
        elif message.is_encrypted:
            display_content = "[Encrypted message - join channel with password]"
        
        # Check for cover traffic
        if is_private and display_content.startswith(COVER_TRAFFIC_PREFIX):
            debug_println(f"[COVER] Discarding dummy message from {sender_nick}")
            return
        
        # Update chat context for private messages
        if is_private:
            self.chat_context.last_private_sender = (packet.sender_id_str, sender_nick)
            self.chat_context.add_dm(sender_nick, packet.sender_id_str)
        
        # Format and display
        timestamp = datetime.now()
        display = format_message_display(
            timestamp,
            sender_nick,
            display_content,
            is_private,
            bool(message.channel),
            message.channel,
            self.nickname if is_private else None,
            self.nickname
        )
        
        print(f"\r\033[K{display}")
        
        if is_private and not isinstance(self.chat_context.current_mode, PrivateDM):
            print("\033[90m» /reply to respond\033[0m")
        
        print("> ", end='', flush=True)
    
    async def handle_fragment(self, packet: BitchatPacket, raw_data: bytes):
        """Handle message fragment"""
        if len(packet.payload) >= 13:
            fragment_id = packet.payload[0:8]
            index = struct.unpack('>H', packet.payload[8:10])[0]
            total = struct.unpack('>H', packet.payload[10:12])[0]
            original_type = packet.payload[12]
            fragment_data = packet.payload[13:]
            
            result = self.fragment_collector.add_fragment(
                fragment_id, index, total, original_type, fragment_data, packet.sender_id_str
            )
            
            if result:
                complete_data, _ = result
                reassembled_packet = parse_bitchat_packet(complete_data)
                await self.handle_packet(reassembled_packet, complete_data)
        
        # Relay fragment if TTL > 1
        if packet.ttl > 1:
            await asyncio.sleep(random.uniform(0.01, 0.05))
            relay_data = bytearray(raw_data)
            relay_data[2] = packet.ttl - 1
            await self.send_packet(bytes(relay_data))
    
    async def handle_key_exchange(self, packet: BitchatPacket):
        """Handle key exchange"""
        try:
            # Convert bytearray to bytes for encryption service
            payload_bytes = bytes(packet.payload) if isinstance(packet.payload, bytearray) else packet.payload
            response = self.encryption_service.process_handshake_message(packet.sender_id_str, payload_bytes)
            if response:
                response_packet = create_bitchat_packet(
                    self.my_peer_id, MessageType.KEY_EXCHANGE, response
                )
                await self.send_packet(response_packet)
            
            if self.encryption_service.is_session_established(packet.sender_id_str):
                debug_println(f"[CRYPTO] Handshake completed with {packet.sender_id_str}")
                # If this is a new peer after reconnection, send our key exchange too
                if packet.sender_id_str not in self.peers:
                    debug_println(f"[CRYPTO] Sending key exchange response to new peer {packet.sender_id_str}")
                    handshake_message = self.encryption_service.initiate_handshake(packet.sender_id_str)
                    key_exchange_packet = create_bitchat_packet(
                        self.my_peer_id, MessageType.KEY_EXCHANGE, handshake_message
                    )
                    await self.send_packet(key_exchange_packet)

        except Exception as e:
            debug_println(f"[CRYPTO] Handshake failed with {packet.sender_id_str}: {e}")
    
    async def handle_noise_handshake_init(self, packet: BitchatPacket):
        """Handle Noise handshake initiation"""
        debug_println(f"[NOISE] Received handshake init from {packet.sender_id_str}")
        debug_println(f"[NOISE] Recipient ID: {packet.recipient_id_str}, My ID: {self.my_peer_id}")
        
        # Check if this handshake is for us
        if packet.recipient_id_str and packet.recipient_id_str != self.my_peer_id:
            debug_println(f"[NOISE] Handshake not for us, ignoring")
            return
            
        # Check payload size 
        payload_size = len(packet.payload)
        debug_println(f"[NOISE] Handshake payload size: {payload_size} bytes")
        debug_println(f"[NOISE] Handshake payload hex: {packet.payload.hex()[:64]}...")
        
        try:
            # Convert bytearray to bytes for encryption service
            payload_bytes = bytes(packet.payload) if isinstance(packet.payload, bytearray) else packet.payload
            response = self.encryption_service.process_handshake_message(packet.sender_id_str, payload_bytes)
            debug_println(f"[NOISE] process_handshake_message returned: {bool(response)}, response size: {len(response) if response else 0}")
            
            if response:
                # Send handshake response with proper recipient
                response_packet = create_bitchat_packet_with_recipient(
                    self.my_peer_id, packet.sender_id_str, MessageType.NOISE_HANDSHAKE_RESP, response, None
                )
                # Set TTL to 3 like iOS
                response_data = bytearray(response_packet)
                response_data[2] = 3
                await self.send_packet(bytes(response_data))
                debug_println(f"[NOISE] Sent handshake response to {packet.sender_id_str}, payload size: {len(response)}")
            
            if self.encryption_service.is_session_established(packet.sender_id_str):
                debug_println(f"[NOISE] Handshake completed with {packet.sender_id_str}")
                # Clear handshake attempt time on success (matching Swift)
                self.handshake_attempt_times.pop(packet.sender_id_str, None)
                peer_nickname = self.peers.get(packet.sender_id_str, Peer()).nickname or packet.sender_id_str
                print(f"\r\033[K\033[92m✓ Secure session established with {peer_nickname}\033[0m")
                print("> ", end='', flush=True)
                # Add small delay before sending pending messages to avoid BLE congestion
                await asyncio.sleep(0.1)
                # Send any pending private messages
                await self.send_pending_private_messages(packet.sender_id_str)
                
        except Exception as e:
            debug_println(f"[NOISE] Handshake init failed with {packet.sender_id_str}: {e}")
            import traceback
            debug_println(f"[NOISE] Handshake error details: {traceback.format_exc()}")
            # Clear any partial handshake state
            self.encryption_service.clear_handshake_state(packet.sender_id_str)
    
    async def handle_noise_handshake_resp(self, packet: BitchatPacket):
        """Handle Noise handshake response"""
        debug_println(f"[NOISE] Received handshake response from {packet.sender_id_str}")
        debug_println(f"[NOISE] Recipient ID: {packet.recipient_id_str}, My ID: {self.my_peer_id}")
        
        # Check if this handshake response is for us
        if packet.recipient_id_str and packet.recipient_id_str != self.my_peer_id:
            debug_println(f"[NOISE] Handshake response not for us, ignoring")
            return
        
        payload_size = len(packet.payload)
        debug_println(f"[NOISE] Handshake response payload size: {payload_size} bytes")
        debug_println(f"[NOISE] Handshake response payload hex: {packet.payload.hex()[:64]}...")
        
        try:
            # Convert bytearray to bytes for encryption service
            payload_bytes = bytes(packet.payload) if isinstance(packet.payload, bytearray) else packet.payload
            response = self.encryption_service.process_handshake_message(packet.sender_id_str, payload_bytes)
            debug_println(f"[NOISE] process_handshake_message returned: {bool(response)}, response size: {len(response) if response else 0}")
            
            if response:
                # Send final handshake message
                final_packet = create_bitchat_packet_with_recipient(
                    self.my_peer_id, packet.sender_id_str, MessageType.NOISE_HANDSHAKE_INIT, response, None  # Continue with same type
                )
                # Set TTL to 3 like iOS
                final_data = bytearray(final_packet)
                final_data[2] = 3
                await self.send_packet(bytes(final_data))
                debug_println(f"[NOISE] Sent final handshake message to {packet.sender_id_str}, payload size: {len(response)}")
            
            if self.encryption_service.is_session_established(packet.sender_id_str):
                debug_println(f"[NOISE] Handshake completed with {packet.sender_id_str}")
                # Clear handshake attempt time on success (matching Swift)
                self.handshake_attempt_times.pop(packet.sender_id_str, None)
                peer_nickname = self.peers.get(packet.sender_id_str, Peer()).nickname or packet.sender_id_str
                print(f"\r\033[K\033[92m✓ Secure session established with {peer_nickname}\033[0m")
                print("> ", end='', flush=True)
                # Add small delay before sending pending messages to avoid BLE congestion
                await asyncio.sleep(0.1)
                # Send any pending private messages
                await self.send_pending_private_messages(packet.sender_id_str)
                
        except Exception as e:
            debug_println(f"[NOISE] Handshake response failed with {packet.sender_id_str}: {e}")
            import traceback
            debug_println(f"[NOISE] Handshake error details: {traceback.format_exc()}")
            # Clear any partial handshake state
            self.encryption_service.clear_handshake_state(packet.sender_id_str)
    
    async def handle_noise_encrypted(self, packet: BitchatPacket, raw_data: bytes):
        """Handle Noise encrypted message"""
        debug_println(f"[NOISE] Received encrypted message from {packet.sender_id_str}")
        
        # Check if sender is blocked
        fingerprint = self.encryption_service.get_peer_fingerprint(packet.sender_id_str)
        if fingerprint and fingerprint in self.blocked_peers:
            debug_println(f"[BLOCKED] Ignoring encrypted message from blocked peer: {packet.sender_id_str}")
            return
        
        try:
            # Convert bytearray to bytes for encryption service
            payload_bytes = bytes(packet.payload) if isinstance(packet.payload, bytearray) else packet.payload
            
            # Decrypt the Noise encrypted payload using the improved method
            decrypted_payload = self.encryption_service.decrypt_from_peer(packet.sender_id_str, payload_bytes)
            debug_println(f"[NOISE] Successfully decrypted {len(decrypted_payload)} bytes from {packet.sender_id_str}")
            
            # The decrypted payload should be a complete BitchatPacket (matching Swift implementation)
            # Swift creates: BitchatPacket(type: MessageType.message, ...) and encrypts the whole packet
            
            try:
                # Check if the decrypted data starts with version 1 (BitchatPacket)
                if len(decrypted_payload) > 0 and decrypted_payload[0] == 1:
                    # Parse the decrypted data as a complete BitchatPacket
                    inner_packet = parse_bitchat_packet(decrypted_payload)
                    if inner_packet:
                        debug_println(f"[NOISE] Decrypted inner packet: type={inner_packet.msg_type.name if hasattr(inner_packet.msg_type, 'name') else inner_packet.msg_type}, sender={inner_packet.sender_id_str}")
                        
                        # Verify this is a MESSAGE packet (as created by Swift)
                        if inner_packet.msg_type == MessageType.MESSAGE:
                            # Parse the message payload from the inner packet
                            try:
                                message = parse_bitchat_message_payload(inner_packet.payload)
                                
                                # Check for duplicates
                                if message.id not in self.processed_messages:
                                    self.bloom.add(message.id)
                                    self.processed_messages.add(message.id)
                                    
                                    # Display the message as private
                                    await self.display_message(message, packet, True)
                                    
                                    # Send ACK
                                    await self.send_delivery_ack(message.id, packet.sender_id_str, True)
                                else:
                                    debug_println(f"[DUPLICATE] Ignoring duplicate encrypted message: {message.id}")
                                    
                            except Exception as e:
                                debug_println(f"[NOISE] Failed to parse inner message payload: {e}")
                        else:
                            debug_println(f"[NOISE] Unexpected inner packet type: {inner_packet.msg_type}, expected MESSAGE")
                            # Handle other types of inner packets if needed
                            await self.handle_packet(inner_packet, decrypted_payload)
                    else:
                        debug_println(f"[NOISE] Failed to parse decrypted data as BitchatPacket")
                else:
                    # Handle non-BitchatPacket data (likely JSON acknowledgments or receipts)
                    debug_println(f"[NOISE] Decrypted data does not start with version 1, likely acknowledgment/receipt")
                    try:
                        # Try to parse as JSON (iOS read receipts/acks start with newline + JSON)
                        data_str = decrypted_payload.decode('utf-8').strip()
                        if data_str.startswith('{') and data_str.endswith('}'):
                            import json
                            ack_data = json.loads(data_str)
                            debug_println(f"[NOISE] Received acknowledgment: {ack_data}")
                            # Handle acknowledgment data if needed
                        else:
                            debug_println(f"[NOISE] Unknown decrypted data format")
                    except Exception as json_e:
                        debug_println(f"[NOISE] Failed to parse as JSON acknowledgment: {json_e}")
                        
            except Exception as e:
                debug_println(f"[NOISE] Error parsing decrypted inner packet: {e}")
                # Log the first few bytes for debugging
                preview = decrypted_payload[:50] if len(decrypted_payload) >= 50 else decrypted_payload
                debug_println(f"[NOISE] Decrypted data preview: {preview.hex() if isinstance(preview, bytes) else preview}")
                
        except Exception as e:
            debug_println(f"[NOISE] Failed to decrypt message from {packet.sender_id_str}: {e}")
            # Check if we have a session with this peer
            if not self.encryption_service.is_session_established(packet.sender_id_str):
                debug_println(f"[NOISE] No session established with {packet.sender_id_str}")
            else:
                debug_println(f"[NOISE] Session exists but decryption failed - possible key sync issue")
                # If it's an InvalidTag error, it might be a nonce sync issue
                if "InvalidTag" in str(e):
                    debug_println(f"[NOISE] InvalidTag suggests nonce desync - this could be from iOS sending acknowledgments")
                    # Don't reset the session here, just log it
                    # The nonce is already incremented by the failed decrypt attempt
    
    async def handle_leave(self, packet: BitchatPacket):
        """Handle leave notification"""
        payload_str = packet.payload.decode('utf-8', errors='ignore').strip()
        
        if payload_str.startswith('#'):
            # Channel leave
            channel = payload_str
            sender_nick = self.peers.get(packet.sender_id_str, Peer()).nickname or packet.sender_id_str
            
            if isinstance(self.chat_context.current_mode, Channel) and \
               self.chat_context.current_mode.name == channel:
                print(f"\r\033[K\033[90m« {sender_nick} left {channel}\033[0m\n> ", end='', flush=True)
            
            debug_println(f"[<-- RECV] {sender_nick} left channel {channel}")
        else:
            # Peer disconnect
            disconnected_peer = self.peers.pop(packet.sender_id_str, None)
            if disconnected_peer and disconnected_peer.nickname:
                print(f"\r\033[K\033[33m{disconnected_peer.nickname} disconnected\033[0m\n> ", end='', flush=True)
                
                # Remove from active DMs
                if disconnected_peer.nickname in self.chat_context.active_dms:
                    del self.chat_context.active_dms[disconnected_peer.nickname]
                    
                # Clear pending messages for this peer
                if packet.sender_id_str in self.pending_private_messages:
                    del self.pending_private_messages[packet.sender_id_str]
                    
                # Clear encryption session for this peer
                self.encryption_service.remove_session(packet.sender_id_str)
                debug_println(f"[NOISE] Cleared session for disconnected peer {packet.sender_id_str}")
                    
                # If we're in a DM with this peer, switch to public
                if isinstance(self.chat_context.current_mode, PrivateDM) and \
                   self.chat_context.current_mode.peer_id == packet.sender_id_str:
                    self.chat_context.switch_to_public()
                    print("\033[90m» Switched to public chat (peer disconnected)\033[0m\n> ", end='', flush=True)
                    
            debug_println(f"[<-- RECV] Peer {packet.sender_id_str} ({payload_str}) has left")
            
            # If this was the last peer, we might be alone now
            if len(self.peers) == 0:
                print("\033[90m» You're now the only one in the network.\033[0m\n> ", end='', flush=True)
    
    async def handle_channel_announce(self, packet: BitchatPacket):
        """Handle channel announcement"""
        payload_str = packet.payload.decode('utf-8', errors='ignore')
        parts = payload_str.split('|')
        
        if len(parts) >= 3:
            channel = parts[0]
            is_protected = parts[1] == '1'
            creator_id = parts[2]
            key_commitment = parts[3] if len(parts) > 3 else ""
            
            debug_println(f"[<-- RECV] Channel announce: {channel} (protected: {is_protected}, owner: {creator_id})")
            
            if creator_id:
                self.channel_creators[channel] = creator_id
            
            if is_protected:
                self.password_protected_channels.add(channel)
                if key_commitment:
                    self.channel_key_commitments[channel] = key_commitment
            else:
                self.password_protected_channels.discard(channel)
                self.channel_keys.pop(channel, None)
                self.channel_key_commitments.pop(channel, None)
            
            self.chat_context.add_channel(channel)
            await self.save_app_state()
    
    async def handle_delivery_ack(self, packet: BitchatPacket, raw_data: bytes):
        """Handle delivery acknowledgment"""
        is_for_us = packet.recipient_id_str == self.my_peer_id if packet.recipient_id_str else False
        
        if is_for_us:
            # Decrypt if needed
            ack_payload = packet.payload
            if packet.ttl == 3 and self.encryption_service.is_session_established(packet.sender_id_str):
                try:
                    ack_payload = self.encryption_service.decrypt_from_peer(packet.sender_id_str, packet.payload)
                except:
                    pass
            
            # Parse ACK
            try:
                ack_data = json.loads(ack_payload)
                ack = DeliveryAck(
                    ack_data['originalMessageID'],
                    ack_data['ackID'],
                    ack_data['recipientID'],
                    ack_data['recipientNickname'],
                    ack_data['timestamp'],
                    ack_data['hopCount']
                )
                
                if self.delivery_tracker.mark_delivered(ack.original_message_id):
                    print(f"\r\u001b[K\u001b[90m✓ Delivered to {ack.recipient_nickname}\u001b[0m\n> ", end='', flush=True)
                    
            except Exception as e:
                debug_println(f"[ACK] Failed to parse delivery ACK: {e}")
                
        elif packet.ttl > 1:
            # Relay ACK
            relay_data = bytearray(raw_data)
            relay_data[2] = packet.ttl - 1
            await self.send_packet(bytes(relay_data))

    async def handle_noise_identity_announce(self, packet: BitchatPacket):
        """Handle Noise identity announcement"""
        try:
            sender_id = packet.sender_id_str
            debug_println(f"[NOISE] Received identity announcement from {sender_id}")
            
            # Skip if it's from ourselves
            if sender_id == self.my_peer_id:
                return
                
            # Try to decode the identity announcement
            announcement = None
            
            # First try binary format, then JSON fallback
            try:
                announcement = self.parse_noise_identity_announcement_binary(packet.payload)
            except Exception as be:
                debug_println(f"[NOISE] Binary decode failed: {be}")
                # Try JSON fallback for compatibility
                try:
                    announcement_data = json.loads(packet.payload.decode('utf-8'))
                    announcement = {
                        'peerID': announcement_data.get('peerID', sender_id),
                        'nickname': announcement_data.get('nickname', 'Unknown'),
                        'publicKey': announcement_data.get('publicKey', ''),
                        'signingPublicKey': announcement_data.get('signingPublicKey', ''),
                        'timestamp': announcement_data.get('timestamp', 0),
                        'signature': announcement_data.get('signature', '')
                    }
                except Exception as je:
                    debug_println(f"[NOISE] JSON decode also failed: {je}")
                    debug_println(f"[NOISE] Raw payload (first 32 bytes): {packet.payload[:32].hex()}")
                    return
            
            if not announcement:
                debug_println(f"[NOISE] Failed to decode identity announcement from {sender_id}")
                return
                
            peer_id = announcement['peerID']
            nickname = announcement['nickname']
            
            debug_println(f"[NOISE] Identity announcement: {peer_id} -> {nickname}")
            
            # Check if this is a new peer
            is_new_peer = peer_id not in self.peers
            
            # Update peer info
            if peer_id not in self.peers:
                self.peers[peer_id] = Peer()
            self.peers[peer_id].nickname = nickname
            
            if is_new_peer:
                print(f"\r\033[K\033[33m{nickname} connected\033[0m\n> ", end='', flush=True)
                debug_println(f"[<-- RECV] Announce: Peer {peer_id} is now known as '{nickname}'")
            
            # Check if we should initiate handshake (lexicographic comparison)
            if self.my_peer_id < peer_id:
                debug_println(f"[NOISE] We should initiate handshake with {peer_id}")
                # Check if we already have a session or ongoing handshake
                if not self.encryption_service.is_session_established(peer_id):
                    try:
                        handshake_message = self.encryption_service.initiate_handshake(peer_id)
                        handshake_packet = create_bitchat_packet_with_recipient(
                            self.my_peer_id, peer_id, MessageType.NOISE_HANDSHAKE_INIT, handshake_message, None
                        )
                        # Set TTL to 3 like iOS
                        handshake_data = bytearray(handshake_packet)
                        handshake_data[2] = 3
                        handshake_packet = bytes(handshake_data)
                        await self.send_packet(handshake_packet)
                        debug_println(f"[NOISE] Initiated handshake with {peer_id}")
                    except Exception as e:
                        debug_println(f"[NOISE] Failed to initiate handshake: {e}")
            else:
                debug_println(f"[NOISE] Waiting for {peer_id} to initiate handshake")
                    
        except Exception as e:
            debug_println(f"[NOISE] Error handling identity announcement: {e}")
            import traceback
            debug_println(f"[NOISE] Identity announce error details: {traceback.format_exc()}")
    
    def parse_noise_identity_announcement_binary(self, data: bytes) -> dict:
        """Parse binary format noise identity announcement matching iOS appendData format"""
        try:
            offset = 0
            
            debug_println(f"[NOISE] Parsing binary announcement, total length: {len(data)}")
            debug_println(f"[NOISE] Raw data (hex): {data.hex()}")
            
            # Read flags byte
            if offset >= len(data):
                debug_println("[NOISE] Error: Not enough data for flags")
                return None
            flags = data[offset]
            offset += 1
            debug_println(f"[NOISE] Flags: 0x{flags:02x}")
            
            # Check if previousPeerID is present (flag bit 0)
            has_previous_peer_id = (flags & 0x01) != 0
            debug_println(f"[NOISE] Has previous peer ID: {has_previous_peer_id}")
            
            # Read peerID (8 bytes)
            if offset + 8 > len(data):
                debug_println(f"[NOISE] Error: Not enough data for peerID, need 8 bytes, have {len(data) - offset}")
                return None
            peer_id = data[offset:offset+8].hex()
            offset += 8
            debug_println(f"[NOISE] Peer ID: {peer_id}")
            
            # Read publicKey using appendData format (1-byte length prefix for 255 max)
            if offset >= len(data):
                debug_println("[NOISE] Error: Not enough data for publicKey length")
                return None
            pub_key_len = data[offset]
            offset += 1
            
            if offset + pub_key_len > len(data):
                debug_println(f"[NOISE] Error: Not enough data for publicKey, need {pub_key_len} bytes, have {len(data) - offset}")
                return None
            public_key = data[offset:offset+pub_key_len]
            offset += pub_key_len
            debug_println(f"[NOISE] Public key length: {pub_key_len}, key: {public_key.hex()}")
            
            # Read signingPublicKey using appendData format (1-byte length prefix for 255 max)
            if offset >= len(data):
                debug_println("[NOISE] Error: Not enough data for signingPublicKey length")
                return None
            signing_key_len = data[offset]
            offset += 1
            
            if offset + signing_key_len > len(data):
                debug_println(f"[NOISE] Error: Not enough data for signingPublicKey, need {signing_key_len} bytes, have {len(data) - offset}")
                return None
            signing_public_key = data[offset:offset+signing_key_len]
            offset += signing_key_len
            debug_println(f"[NOISE] Signing public key length: {signing_key_len}, key: {signing_public_key.hex()}")
            
            # Read nickname using appendString format (1-byte length prefix for 255 max)
            if offset >= len(data):
                debug_println("[NOISE] Error: Not enough data for nickname length")
                return None
            nickname_len = data[offset]
            offset += 1
            debug_println(f"[NOISE] Nickname length: {nickname_len}")
            
            nickname = ""
            if nickname_len > 0:
                if offset + nickname_len > len(data):
                    debug_println(f"[NOISE] Error: Not enough data for nickname, need {nickname_len} bytes, have {len(data) - offset}")
                    return None
                nickname_bytes = data[offset:offset+nickname_len]
                offset += nickname_len
                nickname = nickname_bytes.decode('utf-8')
                debug_println(f"[NOISE] Nickname: '{nickname}'")
            else:
                debug_println("[NOISE] Nickname: (empty)")
            
            # Read timestamp using appendDate format (8-byte UInt64 in milliseconds, big-endian)
            if offset + 8 > len(data):
                debug_println(f"[NOISE] Error: Not enough data for timestamp, need 8 bytes, have {len(data) - offset}")
                return None
            timestamp_ms = int.from_bytes(data[offset:offset+8], byteorder='big')
            offset += 8
            timestamp = timestamp_ms / 1000.0  # Convert from milliseconds to seconds
            debug_println(f"[NOISE] Timestamp: {timestamp} ({timestamp_ms}ms)")
            
            # Read previousPeerID if present (8 bytes)
            previous_peer_id = None
            if has_previous_peer_id:
                if offset + 8 > len(data):
                    debug_println("[NOISE] Error: Not enough data for previousPeerID")
                    return None
                previous_peer_id = data[offset:offset+8].hex()
                offset += 8
                debug_println(f"[NOISE] Previous peer ID: {previous_peer_id}")
            
            # Read signature using appendData format (1-byte length prefix for 255 max)
            if offset >= len(data):
                debug_println("[NOISE] Error: Not enough data for signature length")
                return None
            signature_len = data[offset]
            offset += 1
            
            if offset + signature_len > len(data):
                debug_println(f"[NOISE] Error: Not enough data for signature, need {signature_len} bytes, have {len(data) - offset}")
                return None
            signature = data[offset:offset+signature_len]
            offset += signature_len
            debug_println(f"[NOISE] Signature length: {signature_len}, sig: {signature.hex()}")
            
            debug_println(f"[NOISE] Total parsed {offset} bytes out of {len(data)} available")
            
            return {
                'peerID': peer_id,
                'publicKey': public_key.hex(),
                'signingPublicKey': signing_public_key.hex(),
                'nickname': nickname,
                'timestamp': timestamp,
                'signature': signature.hex(),
                'previousPeerID': previous_peer_id,
                'truncated': False
            }
            
        except Exception as e:
            debug_println(f"[NOISE] Error parsing binary announcement: {e}")
            import traceback
            debug_println(f"[NOISE] Binary parser error details: {traceback.format_exc()}")
            return None
    
    def encode_noise_identity_announcement_binary(self, peer_id: str, public_key: bytes, 
                                                  signing_public_key: bytes, nickname: str, 
                                                  timestamp: int, signature: bytes, 
                                                  previous_peer_id: str = None) -> bytes:
        """Encode noise identity announcement to binary format matching iOS appendData format"""
        data = bytearray()
        
        # Flags byte: bit 0 = hasPreviousPeerID
        flags = 0
        if previous_peer_id:
            flags |= 0x01
        data.append(flags)
        
        # PeerID as 8-byte hex string (match Swift conversion)
        peer_data = bytes.fromhex(peer_id.ljust(16, '0')[:16])  # Pad to 8 bytes
        data.extend(peer_data)
        
        # PublicKey using appendData format (1-byte length prefix since 32 < 255)
        data.append(len(public_key))
        data.extend(public_key)
        
        # SigningPublicKey using appendData format (1-byte length prefix since 32 < 255)
        data.append(len(signing_public_key))
        data.extend(signing_public_key)
        
        # Nickname using appendString format (1-byte length prefix for strings under 255 chars)
        nickname_bytes = nickname.encode('utf-8')
        data.append(len(nickname_bytes))
        data.extend(nickname_bytes)
        
        # Timestamp using appendDate format (8 bytes UInt64 milliseconds, big-endian)
        timestamp_ms = int(timestamp * 1000)  # Convert to milliseconds
        for i in range(8):
            data.append((timestamp_ms >> ((7-i) * 8)) & 0xFF)
        
        # PreviousPeerID if present (8 bytes, after timestamp)
        if previous_peer_id:
            prev_data = bytes.fromhex(previous_peer_id.ljust(16, '0')[:16])  # Pad to 8 bytes
            data.extend(prev_data)
        
        # Signature using appendData format (1-byte length prefix)
        data.append(len(signature))
        data.extend(signature)
        
        return bytes(data)
    
    async def send_delivery_ack(self, message_id: str, sender_id: str, is_private: bool):
        """Send delivery acknowledgment"""
        ack_id = f"{message_id}-{self.my_peer_id}"
        if not self.delivery_tracker.should_send_ack(ack_id):
            return
        
        debug_println(f"[ACK] Sending delivery ACK for message {message_id}")
        
        ack = DeliveryAck(
            message_id,
            str(uuid.uuid4()),
            self.my_peer_id,
            self.nickname,
            int(time.time() * 1000),
            1
        )
        
        ack_payload = json.dumps({
            'originalMessageID': ack.original_message_id,
            'ackID': ack.ack_id,
            'recipientID': ack.recipient_id,
            'recipientNickname': ack.recipient_nickname,
            'timestamp': ack.timestamp,
            'hopCount': ack.hop_count
        }).encode()
        
        # Encrypt if private
        if is_private:
            try:
                ack_payload = self.encryption_service.encrypt(ack_payload, sender_id)
            except:
                pass
        
        # Send ACK packet
        ack_packet = create_bitchat_packet_with_recipient(
            self.my_peer_id,
            sender_id,
            MessageType.DELIVERY_ACK,
            ack_payload,
            None
        )
        
        # Set TTL to 3
        ack_packet_data = bytearray(ack_packet)
        ack_packet_data[2] = 3
        
        await self.send_packet(bytes(ack_packet_data))
    
    async def send_channel_announce(self, channel: str, is_protected: bool, key_commitment: Optional[str]):
        """Send channel announcement"""
        payload = f"{channel}|{'1' if is_protected else '0'}|{self.my_peer_id}|{key_commitment or ''}"
        packet = create_bitchat_packet(
            self.my_peer_id,
            MessageType.CHANNEL_ANNOUNCE,
            payload.encode()
        )
        
        # Set TTL to 5
        packet_data = bytearray(packet)
        packet_data[2] = 5
        
        debug_println(f"[CHANNEL] Sending channel announce for {channel}")
        await self.send_packet(bytes(packet_data))
    
    async def save_app_state(self):
        """Save application state"""
        self.app_state.nickname = self.nickname
        self.app_state.blocked_peers = self.blocked_peers
        self.app_state.channel_creators = self.channel_creators
        self.app_state.joined_channels = self.chat_context.active_channels
        self.app_state.password_protected_channels = self.password_protected_channels
        self.app_state.channel_key_commitments = self.channel_key_commitments
        
        try:
            save_state(self.app_state)
        except Exception as e:
            logging.error(f"Failed to save state: {e}")
    
    async def handle_user_input(self, line: str):
        """Handle user input commands and messages"""
        # Number switching
        if len(line) == 1 and line.isdigit():
            num = int(line)
            if self.chat_context.switch_to_number(num):
                debug_println(self.chat_context.get_status_line())
            else:
                print("» Invalid conversation number")
            return
        
        # Commands
        if line == "/help":
            print_help()
            return
        
        if line == "/exit":
            # Send leave notification if connected
            if self.client and self.client.is_connected:
                leave_packet = create_bitchat_packet(
                    self.my_peer_id, MessageType.LEAVE, self.nickname.encode()
                )
                await self.send_packet(leave_packet)
                await asyncio.sleep(0.1)  # Give time for the packet to send
            
            await self.save_app_state()
            self.running = False
            return
        
        if line.startswith("/name "):
            new_name = line[6:].strip()
            if not new_name:
                print("\033[93m⚠ Usage: /name <new_nickname>\033[0m")
                print("\033[90mExample: /name Alice\033[0m")
            elif len(new_name) > 20:
                print("\033[93m⚠ Nickname too long\033[0m")
                print("\033[90mMaximum 20 characters allowed.\033[0m")
            elif not all(c.isalnum() or c in '-_' for c in new_name):
                print("\033[93m⚠ Invalid nickname\033[0m")
                print("\033[90mNicknames can only contain letters, numbers, hyphens and underscores.\033[0m")
            elif new_name in ["system", "all"]:
                print("\033[93m⚠ Reserved nickname\033[0m")
                print("\033[90mThis nickname is reserved and cannot be used.\033[0m")
            else:
                self.nickname = new_name
                announce_packet = create_bitchat_packet(
                    self.my_peer_id, MessageType.ANNOUNCE, self.nickname.encode()
                )
                await self.send_packet(announce_packet)
                print(f"\033[90m» Nickname changed to: {self.nickname}\033[0m")
                await self.save_app_state()
            return
        
        if line == "/list":
            self.chat_context.show_conversation_list()
            return
        
        if line == "/switch":
            print(f"\n{self.chat_context.get_conversation_list_with_numbers()}")
            switch_input = await aioconsole.ainput("Enter number to switch to: ")
            if switch_input.strip().isdigit():
                num = int(switch_input.strip())
                if self.chat_context.switch_to_number(num):
                    debug_println(self.chat_context.get_status_line())
                else:
                    print("» Invalid selection")
            return
        
        if line.startswith("/j "):
            await self.handle_join_channel(line)
            return
        
        if line == "/public":
            self.chat_context.switch_to_public()
            debug_println(self.chat_context.get_status_line())
            return
        
        if line in ["/online", "/w"]:
            if not self.client or not self.client.is_connected:
                print("» You're not connected to any peers yet.")
                print("\033[90mWaiting for other BitChat devices...\033[0m")
            else:
                online_list = [p.nickname for p in self.peers.values() if p.nickname]
                if online_list:
                    print(f"» Online users: {', '.join(sorted(online_list))}")
                else:
                    print("» No one else is online right now.")
            print("> ", end='', flush=True)
            return
        
        if line == "/channels":
            all_channels = set(self.chat_context.active_channels) | set(self.channel_keys.keys())
            if all_channels:
                print("» Discovered channels:")
                for channel in sorted(all_channels):
                    status = ""
                    if channel in self.chat_context.active_channels:
                        status += " ✓"
                    if channel in self.password_protected_channels:
                        status += " 🔒"
                        if channel in self.channel_keys:
                            status += " 🔑"
                    print(f"  {channel}{status}")
                print("\n✓ = joined, 🔒 = password protected, 🔑 = authenticated")
            else:
                print("» No channels discovered yet. Channels appear as people use them.")
            print("> ", end='', flush=True)
            return
        
        if line == "/status":
            peer_count = len(self.peers)
            channel_count = len(self.chat_context.active_channels)
            dm_count = len(self.chat_context.active_dms)
            connection_status = "Connected" if (self.client and self.client.is_connected) else "Offline"
            session_count = self.encryption_service.get_session_count()
            pending_handshakes = len(self.encryption_service.handshake_states)
            pending_messages = sum(len(msgs) for msgs in self.pending_private_messages.values())
            
            print("\n╭─── Connection Status ──────╮")
            print(f"│ Status: {connection_status:^18} │")
            print(f"│ Peers connected: {peer_count:6}     │")
            print(f"│ Active channels: {channel_count:6}     │")
            print(f"│ Active DMs:      {dm_count:6}     │")
            print("│                           │")
            print(f"│ Secure sessions: {session_count:6}     │")
            print(f"│ Pending handshakes: {pending_handshakes:3}     │")
            print(f"│ Queued messages: {pending_messages:6}     │")
            print("│                           │")
            print(f"│ Your nickname: {self.nickname[:11]:^11}  │")
            print(f"│ Your ID: {self.my_peer_id[:8]}...    │")
            print("╰───────────────────────────╯")
            
            # Show encryption session details if any
            if session_count > 0:
                print("\n🔒 Secure Sessions:")
                for peer_id in self.encryption_service.get_active_peers():
                    nickname = self.peers.get(peer_id, Peer()).nickname or peer_id[:8] + "..."
                    fingerprint = self.encryption_service.get_peer_fingerprint(peer_id)
                    print(f"  • {nickname} ({fingerprint[:8] if fingerprint else 'Unknown'}...)")
            
            # Show pending handshakes if any
            if pending_handshakes > 0:
                print("\n🤝 Pending Handshakes:")
                for peer_id in self.encryption_service.handshake_states.keys():
                    nickname = self.peers.get(peer_id, Peer()).nickname or peer_id[:8] + "..."
                    print(f"  • {nickname}")
            
            # Show pending messages if any
            if pending_messages > 0:
                print("\n📝 Queued Messages:")
                for peer_id, messages in self.pending_private_messages.items():
                    nickname = self.peers.get(peer_id, Peer()).nickname or peer_id[:8] + "..."
                    print(f"  • {len(messages)} message(s) for {nickname}")
            
            print("> ", end='', flush=True)
            return
        
        if line == "/clear":
            clear_screen()
            print_banner()
            mode_name = {
                ChatMode.Public: "public chat",
                ChatMode.Channel: f"channel {self.chat_context.current_mode.name}",
                ChatMode.PrivateDM: f"DM with {self.chat_context.current_mode.nickname}"
            }.get(type(self.chat_context.current_mode), "unknown")
            print(f"» Cleared {mode_name}")
            print("> ", end='', flush=True)
            return
        
        if line.startswith("/dm "):
            await self.handle_dm_command(line)
            return
        
        if line == "/reply":
            if self.chat_context.last_private_sender:
                peer_id, nickname = self.chat_context.last_private_sender
                self.chat_context.enter_dm_mode(nickname, peer_id)
                debug_println(self.chat_context.get_status_line())
            else:
                print("» No private messages received yet.")
            return
        
        if line.startswith("/block"):
            await self.handle_block_command(line)
            return
        
        if line.startswith("/unblock "):
            await self.handle_unblock_command(line)
            return
        
        if line == "/leave":
            await self.handle_leave_command()
            return
        
        if line.startswith("/pass "):
            await self.handle_pass_command(line)
            return
        
        if line.startswith("/transfer "):
            await self.handle_transfer_command(line)
            return
        
        # Unknown command
        if line.startswith("/"):
            cmd = line.split()[0]
            print(f"\033[93m⚠ Unknown command: {cmd}\033[0m")
            print("\033[90mType /help to see available commands.\033[0m")
            return
        
        # Regular message - check mode
        if isinstance(self.chat_context.current_mode, PrivateDM):
            await self.send_private_message(
                line,
                self.chat_context.current_mode.peer_id,
                self.chat_context.current_mode.nickname
            )
        else:
            # Check if we're connected before sending
            if not self.client or not self.client.is_connected:
                print("\033[93m⚠ You're not connected to any peers yet.\033[0m")
                print("\033[90mYour message will be sent once someone joins the network.\033[0m")
                print("\033[90m(This Python client doesn't queue messages while offline)\033[0m")
            else:
                await self.send_public_message(line)
    
    async def handle_join_channel(self, line: str):
        """Handle /j command"""
        parts = line.split()
        if len(parts) < 2:
            print("\033[93m⚠ Usage: /j #<channel> [password]\033[0m")
            print("\033[90mExample: /j #general\033[0m")
            print("\033[90mExample: /j #private mysecret\033[0m")
            return
        
        channel_name = parts[1]
        password = parts[2] if len(parts) > 2 else None
        
        if not channel_name.startswith("#"):
            print("\033[93m⚠ Channel names must start with #\033[0m")
            print(f"\033[90mExample: /j #{channel_name}\033[0m")
            return
        
        if len(channel_name) > 25:
            print("\033[93m⚠ Channel name too long\033[0m")
            print("\033[90mMaximum 25 characters allowed.\033[0m")
            return
        
        if not all(c.isalnum() or c in '-_' for c in channel_name[1:]):
            print("\033[93m⚠ Invalid channel name\033[0m")
            print("\033[90mChannel names can only contain letters, numbers, hyphens and underscores.\033[0m")
            return
        
        # Check if password protected
        if channel_name in self.password_protected_channels:
            if channel_name in self.channel_keys:
                # We have the key
                self.discovered_channels.add(channel_name)
                self.chat_context.switch_to_channel(channel_name)
                print("> ", end='', flush=True)
                return
            
            if not password:
                print(f"❌ Channel {channel_name} is password-protected. Use: /j {channel_name} <password>")
                return
            
            if len(password) < 4:
                print("\033[93m⚠ Password too short\033[0m")
                print("\033[90mMinimum 4 characters required.\033[0m")
                return
            
            key = EncryptionService.derive_channel_key(password, channel_name)
            
            # Verify password
            if channel_name in self.channel_key_commitments:
                test_commitment = hashlib.sha256(key).hexdigest()
                if test_commitment != self.channel_key_commitments[channel_name]:
                    print(f"❌ wrong password for channel {channel_name}. please enter the correct password.")
                    return
            
            self.channel_keys[channel_name] = key
            self.discovered_channels.add(channel_name)
            
            # Save encrypted password
            if self.app_state.identity_key:
                try:
                    encrypted = encrypt_password(password, self.app_state.identity_key)
                    self.app_state.encrypted_channel_passwords[channel_name] = encrypted
                    await self.save_app_state()
                except Exception as e:
                    debug_println(f"[CHANNEL] Failed to encrypt password: {e}")
            
            self.chat_context.switch_to_channel_silent(channel_name)
            print("\r\033[K\033[90m─────────────────────────\033[0m")
            print(f"\033[90m» Joined password-protected channel: {channel_name} 🔒\033[0m")
            
            # Send channel announce
            if channel_name in self.channel_creators:
                key_commitment = hashlib.sha256(key).hexdigest()
                await self.send_channel_announce(channel_name, True, key_commitment)
            
            print("> ", end='', flush=True)
        else:
            # Not password protected
            if password:
                key = EncryptionService.derive_channel_key(password, channel_name)
                self.channel_keys[channel_name] = key
                self.discovered_channels.add(channel_name)
                self.chat_context.switch_to_channel_silent(channel_name)
                print("\r\033[K\033[90m─────────────────────────\033[0m")
                print(f"\033[90m» Joined password-protected channel: {channel_name} 🔒. Just type to send messages.\033[0m")
                
                if channel_name in self.channel_creators:
                    key_commitment = hashlib.sha256(key).hexdigest()
                    await self.send_channel_announce(channel_name, True, key_commitment)
                
                print("> ", end='', flush=True)
            else:
                # Regular channel
                self.discovered_channels.add(channel_name)
                print("\r\033[K", end='')
                self.chat_context.switch_to_channel(channel_name)
                self.channel_keys.pop(channel_name, None)
                print("> ", end='', flush=True)
        
        debug_println(self.chat_context.get_status_line())
    
    async def handle_dm_command(self, line: str):
        """Handle /dm command"""
        if not self.client or not self.client.is_connected:
            print("\033[93m⚠ Not connected to the BitChat network yet.\033[0m")
            print("\033[90mWait for a connection before sending direct messages.\033[0m")
            return
            
        parts = line.split(maxsplit=2)
        
        if len(parts) < 2:
            print("\033[93m⚠ Usage: /dm <nickname> [message]\033[0m")
            print("\033[90mExample: /dm Bob Hey there!\033[0m")
            return
        
        target_nickname = parts[1]
        message = parts[2] if len(parts) > 2 else None
        
        # Find peer
        target_peer_id = None
        for peer_id, peer in self.peers.items():
            if peer.nickname == target_nickname:
                target_peer_id = peer_id
                break
        
        if not target_peer_id:
            print(f"\033[93m⚠ User '{target_nickname}' not found\033[0m")
            print("\033[90mThey may be offline or using a different nickname.\033[0m")
            return
        
        if message:
            # Send message directly
            await self.send_private_message(message, target_peer_id, target_nickname)
        else:
            # Enter DM mode
            self.chat_context.enter_dm_mode(target_nickname, target_peer_id)
            debug_println(self.chat_context.get_status_line())
    
    async def handle_block_command(self, line: str):
        """Handle /block command"""
        parts = line.split()
        
        if len(parts) == 1:
            # List blocked
            if self.blocked_peers:
                blocked_nicks = []
                for peer_id, peer in self.peers.items():
                    fingerprint = self.encryption_service.get_peer_fingerprint(peer_id)
                    if fingerprint and fingerprint in self.blocked_peers and peer.nickname:
                        blocked_nicks.append(peer.nickname)
                
                if blocked_nicks:
                    print(f"» Blocked peers: {', '.join(blocked_nicks)}")
                else:
                    print(f"» Blocked peers (not currently online): {len(self.blocked_peers)}")
            else:
                print("» No blocked peers.")
        elif len(parts) == 2:
            # Block a peer
            target = parts[1].lstrip('@')
            
            # Find peer
            target_peer_id = None
            for peer_id, peer in self.peers.items():
                if peer.nickname == target:
                    target_peer_id = peer_id
                    break
            
            if target_peer_id:
                fingerprint = self.encryption_service.get_peer_fingerprint(target_peer_id)
                if fingerprint:
                    if fingerprint in self.blocked_peers:
                        print(f"» {target} is already blocked.")
                    else:
                        self.blocked_peers.add(fingerprint)
                        await self.save_app_state()
                        print(f"\n\033[92m✓ Blocked {target}\033[0m")
                        print(f"\033[90m{target} will no longer be able to send you messages.\033[0m")
                else:
                    print(f"» Cannot block {target}: No identity key received yet.")
            else:
                print(f"\033[93m⚠ User '{target}' not found\033[0m")
                print("\033[90mThey may be offline or haven't sent any messages yet.\033[0m")
        else:
            print("\033[93m⚠ Usage: /block @<nickname>\033[0m")
            print("\033[90mExample: /block @spammer\033[0m")
    
    async def handle_unblock_command(self, line: str):
        """Handle /unblock command"""
        parts = line.split()
        
        if len(parts) != 2:
            print("\033[93m⚠ Usage: /unblock @<nickname>\033[0m")
            print("\033[90mExample: /unblock @friend\033[0m")
            return
        
        target = parts[1].lstrip('@')
        
        # Find peer
        target_peer_id = None
        for peer_id, peer in self.peers.items():
            if peer.nickname == target:
                target_peer_id = peer_id
                break
        
        if target_peer_id:
            fingerprint = self.encryption_service.get_peer_fingerprint(target_peer_id)
            if fingerprint:
                if fingerprint in self.blocked_peers:
                    self.blocked_peers.remove(fingerprint)
                    await self.save_app_state()
                    print(f"\n\033[92m✓ Unblocked {target}\033[0m")
                    print(f"\033[90m{target} can now send you messages again.\033[0m")
                else:
                    print(f"\033[93m⚠ {target} is not blocked\033[0m")
            else:
                print(f"» Cannot unblock {target}: No identity key received.")
        else:
            print(f"\033[93m⚠ User '{target}' not found\033[0m")
            print("\033[90mThey may be offline or haven't sent any messages yet.\033[0m")
    
    async def handle_leave_command(self):
        """Handle /leave command"""
        if isinstance(self.chat_context.current_mode, Channel):
            channel = self.chat_context.current_mode.name
            
            # Send leave notification
            leave_payload = channel.encode()
            leave_packet = create_bitchat_packet(
                self.my_peer_id, MessageType.LEAVE, leave_payload
            )
            
            # Set TTL to 3
            leave_packet_data = bytearray(leave_packet)
            leave_packet_data[2] = 3
            
            await self.send_packet(bytes(leave_packet_data))
            
            # Clean up
            self.channel_keys.pop(channel, None)
            self.password_protected_channels.discard(channel)
            self.channel_creators.pop(channel, None)
            self.channel_key_commitments.pop(channel, None)
            self.app_state.encrypted_channel_passwords.pop(channel, None)
            
            self.chat_context.remove_channel(channel)
            self.chat_context.switch_to_public()
            
            await self.save_app_state()
            
            print(f"\033[90m» Left channel {channel}\033[0m")
            print("> ", end='', flush=True)
        else:
            print("» You're not in a channel. Use /j #channel to join one.")
    
    async def handle_pass_command(self, line: str):
        """Handle /pass command"""
        if not isinstance(self.chat_context.current_mode, Channel):
            print("» You must be in a channel to use /pass.")
            return
        
        channel = self.chat_context.current_mode.name
        parts = line.split(maxsplit=1)
        
        if len(parts) < 2:
            print("\033[93m⚠ Usage: /pass <new password>\033[0m")
            print("\033[90mExample: /pass mysecret123\033[0m")
            return
        
        new_password = parts[1]
        
        if len(new_password) < 4:
            print("\033[93m⚠ Password too short\033[0m")
            print("\033[90mMinimum 4 characters required.\033[0m")
            return
        
        # Check ownership
        owner = self.channel_creators.get(channel)
        if owner and owner != self.my_peer_id:
            print("» Only the channel owner can change the password.")
            return
        
        # Claim ownership if no owner
        if not owner:
            self.channel_creators[channel] = self.my_peer_id
            debug_println(f"[CHANNEL] Claiming ownership of {channel}")
        
        # Update password
        old_key = self.channel_keys.get(channel)
        new_key = EncryptionService.derive_channel_key(new_password, channel)
        
        self.channel_keys[channel] = new_key
        self.password_protected_channels.add(channel)
        
        # Save encrypted password
        if self.app_state.identity_key:
            try:
                encrypted = encrypt_password(new_password, self.app_state.identity_key)
                self.app_state.encrypted_channel_passwords[channel] = encrypted
            except Exception as e:
                debug_println(f"[CHANNEL] Failed to encrypt password: {e}")
        
        # Calculate commitment
        commitment_hex = hashlib.sha256(new_key).hexdigest()
        self.channel_key_commitments[channel] = commitment_hex
        
        # Send notification with old key if exists
        if old_key:
            notify_msg = "🔐 Password changed by channel owner. Please update your password."
            try:
                encrypted_notify = self.encryption_service.encrypt_with_key(notify_msg.encode(), old_key)
                notify_payload, _ = create_encrypted_channel_message_payload(
                    self.nickname, notify_msg, channel, old_key, self.encryption_service, self.my_peer_id
                )
                notify_packet = create_bitchat_packet(self.my_peer_id, MessageType.MESSAGE, notify_payload)
                await self.send_packet(notify_packet)
            except:
                pass
        
        # Send channel announce
        await self.send_channel_announce(channel, True, commitment_hex)
        
        # Send init message
        init_msg = f"🔑 Password {'changed' if old_key else 'set'} | Channel {channel} password {'updated' if old_key else 'protected'} by {self.nickname} | Metadata: {self.my_peer_id.encode().hex()}"
        init_payload, _ = create_encrypted_channel_message_payload(
            self.nickname, init_msg, channel, new_key, self.encryption_service, self.my_peer_id
        )
        init_packet = create_bitchat_packet(self.my_peer_id, MessageType.MESSAGE, init_payload)
        await self.send_packet(init_packet)
        
        await self.save_app_state()
        
        print(f"» Password {'changed' if old_key else 'set'} for {channel}.")
        print(f"» Members will need to rejoin with: /j {channel} {new_password}")
    
    async def handle_transfer_command(self, line: str):
        """Handle /transfer command"""
        if not isinstance(self.chat_context.current_mode, Channel):
            print("» You must be in a channel to use /transfer.")
            return
        
        channel = self.chat_context.current_mode.name
        parts = line.split()
        
        if len(parts) != 2:
            print("\033[93m⚠ Usage: /transfer @<username>\033[0m")
            print("\033[90mExample: /transfer @newowner\033[0m")
            return
        
        # Check ownership
        owner_id = self.channel_creators.get(channel)
        if owner_id != self.my_peer_id:
            print("» Only the channel owner can transfer ownership.")
            return
        
        target = parts[1].lstrip('@')
        
        # Find peer
        new_owner_id = None
        for peer_id, peer in self.peers.items():
            if peer.nickname == target:
                new_owner_id = peer_id
                break
        
        if not new_owner_id:
            print(f"\033[93m⚠ User '{target}' not found\033[0m")
            print("\033[90mMake sure they are online and you have the correct nickname.\033[0m")
            return
        
        # Transfer ownership
        self.channel_creators[channel] = new_owner_id
        await self.save_app_state()
        
        # Send announce
        is_protected = channel in self.password_protected_channels
        key_commitment = None
        if is_protected and channel in self.channel_keys:
            key_commitment = hashlib.sha256(self.channel_keys[channel]).hexdigest()
        
        await self.send_channel_announce(channel, is_protected, key_commitment)
        
        print(f"» Transferred ownership of {channel} to {target}")
    
    async def send_public_message(self, content: str):
        """Send a public or channel message"""
        if not self.client or not self.characteristic:
            print("\033[93m⚠ Not connected to any peers yet.\033[0m")
            print("\033[90mYour message will be sent once a connection is established.\033[0m")
            return
            
        current_channel = None
        if isinstance(self.chat_context.current_mode, Channel):
            current_channel = self.chat_context.current_mode.name
            
            # Check if password protected
            if current_channel in self.password_protected_channels and current_channel not in self.channel_keys:
                print(f"❌ Cannot send to password-protected channel {current_channel}. Join with password first.")
                return
        
        # Create message payload
        if current_channel and current_channel in self.channel_keys:
            # Encrypted channel message
            creator_fingerprint = self.channel_creators.get(current_channel, '')
            encrypted_content = self.encryption_service.encrypt_for_channel(content, current_channel, self.channel_keys[current_channel], creator_fingerprint)
            payload, message_id = create_bitchat_message_payload_full(
                self.nickname, content, current_channel, False, self.my_peer_id, True, encrypted_content
            )
        else:
            # Regular message
            payload, message_id = create_bitchat_message_payload_full(
                self.nickname, content, current_channel, False, self.my_peer_id, False, None
            )
        
        # Track for delivery
        self.delivery_tracker.track_message(message_id, content, False)
        
        message_packet = create_bitchat_packet(
            self.my_peer_id, MessageType.MESSAGE, payload
        )
        
        await self.send_packet(message_packet)
        
        # Display sent message
        timestamp = datetime.now()
        display = format_message_display(
            timestamp,
            self.nickname,
            content,
            False,
            bool(current_channel),
            current_channel,
            None,
            self.nickname
        )
        print(f"\x1b[1A\r\033[K{display}")
    
    async def send_private_message(self, content: str, target_peer_id: str, target_nickname: str, message_id: Optional[str] = None):
        """Send a private encrypted message"""
        if not self.client or not self.characteristic:
            print("\033[93m⚠ Not connected to any peers yet.\033[0m")
            return

        # Check if we have a Noise session with this peer
        if not self.encryption_service.is_session_established(target_peer_id):
            debug_println(f"[NOISE] No session with {target_peer_id}, need to establish handshake")
            
            # Queue message for sending after handshake completes
            msg_id = message_id if message_id else str(uuid.uuid4())
            if target_peer_id not in self.pending_private_messages:
                self.pending_private_messages[target_peer_id] = []
            self.pending_private_messages[target_peer_id].append((content, target_nickname, msg_id))
            debug_println(f"[NOISE] Queued private message for {target_peer_id}, {len(self.pending_private_messages[target_peer_id])} messages pending")
            
            # Always initiate handshake for private messages since user explicitly requested it
            debug_println(f"[NOISE] Initiating handshake with {target_peer_id} for private message")
            
            # Check if we've recently tried to handshake with this peer (matching Swift logic)
            current_time = time.time()
            if target_peer_id in self.handshake_attempt_times:
                last_attempt = self.handshake_attempt_times[target_peer_id]
                if current_time - last_attempt < self.handshake_timeout:
                    debug_println(f"[NOISE] Skipping handshake with {target_peer_id} - too recent (last attempt {current_time - last_attempt:.1f}s ago)")
                    print(f"\033[90m» Handshake already in progress with {target_nickname}, please wait...\033[0m")
                    return
            
            # Record handshake attempt time
            self.handshake_attempt_times[target_peer_id] = current_time
            
            try:
                handshake_message = self.encryption_service.initiate_handshake(target_peer_id)
                handshake_packet = create_bitchat_packet_with_recipient(
                    self.my_peer_id, target_peer_id, MessageType.NOISE_HANDSHAKE_INIT, handshake_message, None
                )
                # Set TTL to 3 like iOS
                handshake_data = bytearray(handshake_packet)
                handshake_data[2] = 3
                handshake_packet = bytes(handshake_data)
                await self.send_packet(handshake_packet)
                debug_println(f"[NOISE] Sent handshake init to {target_peer_id}, payload size: {len(handshake_message)}")
            except Exception as e:
                debug_println(f"[NOISE] Failed to initiate handshake: {e}")
                # Clear the attempt time on failure so we can retry sooner
                self.handshake_attempt_times.pop(target_peer_id, None)
                print(f"\033[91m✗ Failed to initiate secure connection with {target_nickname}\033[0m")
                return
            
            print(f"\033[90m» Initiating secure handshake with {target_nickname}...\033[0m")
            print(f"\033[90m» Your message will be sent automatically once the handshake completes.\033[0m")
            return
            
        debug_println(f"[PRIVATE] Sending encrypted message to {target_nickname}")
        
        # Create message payload - don't set is_encrypted=True since encryption happens at Noise layer
        payload, message_id = create_bitchat_message_payload_full(
            self.nickname, content, None, True, self.my_peer_id, False, None
        )
        
        debug_println(f"[PRIVATE] Created message payload: {len(payload)} bytes")
        debug_println(f"[PRIVATE] Message payload hex: {payload.hex()}")
        
        # Track for delivery
        self.delivery_tracker.track_message(message_id, content, True)
        
        # Create INNER packet (BitchatPacket with MESSAGE type) that will be encrypted
        # This matches Swift implementation: BitchatPacket(type: MessageType.message, ...)
        inner_packet = create_bitchat_packet_with_recipient(
            self.my_peer_id,
            target_peer_id,
            MessageType.MESSAGE,
            payload,
            None
        )
        
        # Set TTL for inner packet (matching Swift's adaptiveTTL behavior)
        inner_packet_data = bytearray(inner_packet)
        inner_packet_data[2] = 7  # TTL for inner packet
        inner_packet = bytes(inner_packet_data)
        
        debug_println(f"[PRIVATE] Created inner packet: {len(inner_packet)} bytes")
        
        try:
            # Encrypt the ENTIRE inner packet using Noise (matching Swift)
            encrypted = self.encryption_service.encrypt_for_peer(target_peer_id, inner_packet)
            debug_println(f"[PRIVATE] Encrypted inner packet: {len(encrypted)} bytes")
            
            # Create outer Noise encrypted packet
            packet = create_bitchat_packet_with_recipient(
                self.my_peer_id,
                target_peer_id,
                MessageType.NOISE_ENCRYPTED,
                encrypted,
                None
            )
            
            # Send with better error handling for BLE issues
            try:
                await self.send_packet(packet)
                
                # Display sent message
                timestamp = datetime.now()
                display = format_message_display(
                    timestamp,
                    self.nickname,
                    content,
                    True,
                    False,
                    None,
                    target_nickname,
                    self.nickname
                )
                print(f"\x1b[1A\r\033[K{display}")
                
            except Exception as send_error:
                # Handle BLE send errors specifically
                if "could not complete without blocking" in str(send_error):
                    debug_println(f"[PRIVATE] BLE write blocked, will retry after longer delay")
                    try:
                        print(f"\033[90m» Message queued (BLE congestion), retrying...\033[0m")
                    except BlockingIOError:
                        pass  # Ignore even print errors
                    
                    # Retry after a longer delay
                    await asyncio.sleep(0.5)
                    try:
                        await self.send_packet(packet)
                        
                        # Display sent message on successful retry
                        timestamp = datetime.now()
                        display = format_message_display(
                            timestamp,
                            self.nickname,
                            content,
                            True,
                            False,
                            None,
                            target_nickname,
                            self.nickname
                        )
                        print(f"\x1b[1A\r\033[K{display}")
                        debug_println(f"[PRIVATE] Message sent successfully on retry")
                        
                    except Exception as retry_error:
                        debug_println(f"[PRIVATE] Retry also failed: {retry_error}")
                        try:
                            print(f"\033[91m✗ Failed to send message (BLE congestion)\033[0m")
                            print(f"\033[90m» Try again in a moment\033[0m")
                        except BlockingIOError:
                            pass  # Ignore print errors
                else:
                    # Other errors - re-raise
                    raise send_error
            
        except Exception as e:
            debug_println(f"[PRIVATE] Failed to encrypt private message: {e}")
            print(f"\033[91m✗ Failed to send encrypted message to {target_nickname}\033[0m")
            print(f"\033[90m» Error: {e}\033[0m")
    
    async def background_scanner(self):
        """Background task to scan for peers when not connected"""
        last_cleanup = time.time()
        
        while self.running:
            # Clean up old sessions periodically (every 5 minutes)
            current_time = time.time()
            if current_time - last_cleanup > 300:  # 5 minutes
                self.encryption_service.cleanup_old_sessions()
                last_cleanup = current_time
                debug_println(f"[CLEANUP] Cleaned up old encryption sessions")
            
            if not self.client or not self.client.is_connected:
                # Try to find and connect to a peer
                device = await self.find_device()
                if device:
                    print(f"\r\033[K\033[92m» Found a BitChat device! Connecting...\033[0m")
                    try:
                        self.client = BleakClient(device.address, disconnected_callback=self.handle_disconnect)
                        await self.client.connect()
                        
                        # Find characteristic
                        services = self.client.services
                        for service in services:
                            for char in service.characteristics:
                                if char.uuid.lower() == BITCHAT_CHARACTERISTIC_UUID.lower():
                                    self.characteristic = char
                                    break
                            if self.characteristic:
                                break
                        
                        if self.characteristic:
                            # Subscribe to notifications
                            await self.client.start_notify(self.characteristic, self.notification_handler)
                            print(f"\r\033[K\033[92m✓ Connected to BitChat network!\033[0m")
                            
                            # Clear any stale peers from previous connection
                            self.peers.clear()
                            
                            # Send Noise identity announcement
                            try:
                                timestamp_ms = int(time.time() * 1000)
                                public_key_bytes = self.encryption_service.get_public_key()
                                signing_public_key_bytes = self.encryption_service.get_signing_public_key_bytes()
                                
                                # Create binding data for signature
                                timestamp_data = str(timestamp_ms).encode('utf-8')
                                binding_data = self.my_peer_id.encode('utf-8') + public_key_bytes + timestamp_data
                                signature = self.encryption_service.sign_data(binding_data)
                                
                                # Encode to binary format
                                identity_payload = self.encode_noise_identity_announcement_binary(
                                    self.my_peer_id, public_key_bytes, signing_public_key_bytes,
                                    self.nickname, timestamp_ms, signature
                                )
                                
                                identity_packet = create_bitchat_packet_with_signature(
                                    self.my_peer_id, MessageType.NOISE_IDENTITY_ANNOUNCE, identity_payload, signature
                                )
                                await self.send_packet(identity_packet)
                            except Exception as e:
                                debug_println(f"[SCANNER] Failed to send identity: {e}")
                                # Fallback
                                key_exchange_payload = self.encryption_service.get_combined_public_key_data()
                                key_exchange_packet = create_bitchat_packet(
                                    self.my_peer_id, MessageType.KEY_EXCHANGE, key_exchange_payload
                                )
                                await self.send_packet(key_exchange_packet)
                            
                            await asyncio.sleep(0.5)
                            
                            announce_packet = create_bitchat_packet(
                                self.my_peer_id, MessageType.ANNOUNCE, self.nickname.encode()
                            )
                            await self.send_packet(announce_packet)
                            
                            print("> ", end='', flush=True)
                    except Exception as e:
                        debug_println(f"[SCANNER] Connection attempt failed: {e}")
                        self.client = None
                        self.characteristic = None
            
            # Wait before next scan
            await asyncio.sleep(5)  # Scan every 5 seconds when not connected
    
    async def input_loop(self):
        """Handle user input asynchronously"""
        while self.running:
            try:
                line = await aioconsole.ainput("> ")
                await self.handle_user_input(line)
            except KeyboardInterrupt:
                self.running = False
                break
            except Exception as e:
                debug_println(f"[ERROR] Input error: {e}")
    
    async def run(self):
        """Main run loop"""
        print_banner()
        
        # Parse command line arguments
        global DEBUG_LEVEL
        if "-dd" in sys.argv or "--debug-full" in sys.argv:
            DEBUG_LEVEL = DebugLevel.FULL
            print("🐛 Debug mode: FULL (verbose output)")
        elif "-d" in sys.argv or "--debug" in sys.argv:
            DEBUG_LEVEL = DebugLevel.BASIC
            print("🐛 Debug mode: BASIC (connection info)")
        
        # Connect to BLE
        connected = await self.connect()
        
        # Perform handshake (will work even without connection)
        await self.handshake()
        
        # Start background scanner if not connected
        scanner_task = None
        if not connected or not self.client:
            scanner_task = asyncio.create_task(self.background_scanner())
        
        # Run input loop
        try:
            await self.input_loop()
        except KeyboardInterrupt:
            pass
        finally:
            debug_println("\n[+] Disconnecting...")
            self.running = False
            
            # Send leave notification if connected
            if self.client and self.client.is_connected:
                try:
                    leave_packet = create_bitchat_packet(
                        self.my_peer_id, MessageType.LEAVE, self.nickname.encode()
                    )
                    await self.send_packet(leave_packet)
                    await asyncio.sleep(0.1)  # Give time for the packet to send
                except:
                    pass  # Ignore errors during shutdown
            
            # Cancel background scanner
            if scanner_task:
                scanner_task.cancel()
                try:
                    await scanner_task
                except asyncio.CancelledError:
                    pass
            
            if self.client and self.client.is_connected:
                await self.client.disconnect()

# Helper functions

def print_banner():
    """Print the BitChat banner"""
    print("\n\033[38;5;46m##\\       ##\\   ##\\               ##\\                  ##\\")
    print("## |      \\__|  ## |              ## |                 ## |")
    print("#######\\  ##\\ ######\\    #######\\ #######\\   ######\\ ######\\")
    print("##  __##\\ ## |\\_##  _|  ##  _____|##  __##\\  \\____##\\\\_##  _|")
    print("## |  ## |## |  ## |    ## /      ## |  ## | ####### | ## |")
    print("## |  ## |## |  ## |##\\ ## |      ## |  ## |##  __## | ## |##\\")
    print("#######  |## |  \\####  |\\#######\\ ## |  ## |\\####### | \\####  |")
    print("\\_______/ \\__|   \\____/  \\_______|\\__|  \\__| \\_______|  \\____/\033[0m")
    print("\n\033[38;5;40m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")
    print("\033[37mDecentralized • Encrypted • Peer-to-Peer • Open Source\033[0m")
    print(f"\033[37m         bitchat@-python {VERSION} @kaganisildak\033[0m")
    print("\033[38;5;40m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n")

def unpad_packet(data: bytes) -> bytes:
    """Remove PKCS#7 padding from packet data (matching iOS implementation)"""
    if len(data) == 0:
        return data
    
    # Last byte tells us how much padding to remove
    padding_length = int(data[-1])
    
    # Validate padding (matching iOS logic exactly)
    if padding_length <= 0 or padding_length > len(data):
        return data  # No padding or invalid padding
    
    # Remove the indicated number of bytes
    result = data[:-padding_length]
    return result

def parse_bitchat_packet(data: bytes) -> BitchatPacket:
    """Parse a BitChat packet from raw bytes"""
    HEADER_SIZE = 13
    SENDER_ID_SIZE = 8
    RECIPIENT_ID_SIZE = 8
    
    # Don't remove padding here - we need to parse the header first to know the actual packet size
    # The iOS client expects properly structured packets with padding intact during parsing
    
    if len(data) < HEADER_SIZE + SENDER_ID_SIZE:
        raise ValueError("Packet too small")
    
    offset = 0
    
    # Version
    version = data[offset]
    offset += 1
    if version != 1:
        raise ValueError("Unsupported version")
    
    # Type
    msg_type = MessageType(data[offset])
    offset += 1
    
    # TTL
    ttl = data[offset]
    offset += 1
    
    # Timestamp (skip)
    offset += 8
    
    # Flags
    flags = data[offset]
    offset += 1
    has_recipient = (flags & FLAG_HAS_RECIPIENT) != 0
    has_signature = (flags & FLAG_HAS_SIGNATURE) != 0
    is_compressed = (flags & FLAG_IS_COMPRESSED) != 0
    
    # Payload length
    payload_len = struct.unpack('>H', data[offset:offset+2])[0]
    offset += 2
    
    # Sender ID (trim null bytes)
    sender_id_raw = data[offset:offset+SENDER_ID_SIZE]
    # Remove trailing null bytes
    sender_id = sender_id_raw.rstrip(b'\x00')
    sender_id_str = sender_id.hex()
    offset += SENDER_ID_SIZE
    
    # Recipient ID
    recipient_id = None
    recipient_id_str = None
    if has_recipient:
        recipient_id_raw = data[offset:offset+RECIPIENT_ID_SIZE]
        # Remove trailing null bytes
        recipient_id = recipient_id_raw.rstrip(b'\x00')
        recipient_id_str = recipient_id.hex()
        offset += RECIPIENT_ID_SIZE
    
    # Payload
    payload_end = offset + payload_len
    payload = data[offset:payload_end]
    offset = payload_end

    # Signature
    signature = None
    if has_signature:
        if len(data) >= offset + SIGNATURE_SIZE:
            signature = data[offset:offset+SIGNATURE_SIZE]
        else:
            debug_println(f"[WARN] Packet has signature flag but not enough data for signature.")
    
    # Decompress if needed
    if is_compressed:
        payload = decompress(payload)
    
    # Ensure payload is bytes
    if isinstance(payload, bytearray):
        payload = bytes(payload)
    
    return BitchatPacket(
        msg_type, sender_id, sender_id_str,
        recipient_id, recipient_id_str, payload, ttl
    )

def parse_bitchat_message_payload(data: bytes) -> BitchatMessage:
    """Parse message payload, matching Swift implementation"""
    offset = 0

    # 1. Flags
    flags = data[offset]; offset += 1
    is_private = (flags & MSG_FLAG_IS_PRIVATE) != 0
    has_sender_peer_id = (flags & MSG_FLAG_HAS_SENDER_PEER_ID) != 0
    has_channel = (flags & MSG_FLAG_HAS_CHANNEL) != 0
    is_encrypted = (flags & MSG_FLAG_IS_ENCRYPTED) != 0

    # 2. Timestamp
    offset += 8 # Skip timestamp

    # 3. ID
    id_len = data[offset]; offset += 1
    id_str = data[offset:offset+id_len].decode('utf-8'); offset += id_len

    # 4. Sender
    sender_len = data[offset]; offset += 1
    sender = data[offset:offset+sender_len].decode('utf-8'); offset += sender_len

    # 5. Content
    content_len = struct.unpack('>H', data[offset:offset+2])[0]; offset += 2
    content_bytes = data[offset:offset+content_len]; offset += content_len
    content = ""
    encrypted_content = None
    if is_encrypted:
        encrypted_content = content_bytes
    else:
        content = content_bytes.decode('utf-8', errors='ignore')

    # 6. Sender Peer ID
    if has_sender_peer_id:
        peer_id_len = data[offset]; offset += 1
        offset += peer_id_len # Skip peer id

    # 7. Channel
    channel = None
    if has_channel:
        channel_len = data[offset]; offset += 1
        channel = data[offset:offset+channel_len].decode('utf-8')

    return BitchatMessage(id_str, content, channel, is_encrypted, encrypted_content)

def create_bitchat_packet(sender_id: str, msg_type: MessageType, payload: bytes) -> bytes:
    """Create a BitChat packet"""
    return create_bitchat_packet_with_recipient(sender_id, None, msg_type, payload, None)

def create_bitchat_packet_with_signature(sender_id: str, msg_type: MessageType, 
                                        payload: bytes, signature: Optional[bytes]) -> bytes:
    """Create a BitChat packet with signature"""
    return create_bitchat_packet_with_recipient(sender_id, None, msg_type, payload, signature)

def create_bitchat_packet_with_recipient_and_signature(sender_id: str, recipient_id: str,
                                                      msg_type: MessageType, payload: bytes,
                                                      signature: Optional[bytes]) -> bytes:
    """Create a BitChat packet with recipient and signature"""
    return create_bitchat_packet_with_recipient(sender_id, recipient_id, msg_type, payload, signature)

def create_bitchat_packet_with_recipient(sender_id: str, recipient_id: Optional[str],
                                       msg_type: MessageType, payload: bytes,
                                       signature: Optional[bytes]) -> bytes:
    """Create a BitChat packet with all options"""
    debug_full_println(f"[RAW SEND] Creating packet: type={msg_type.name}, payload_len={len(payload)}")
    
    # Create the packet first
    packet = bytearray()
    
    # Version
    packet.append(1)
    
    # Type
    packet.append(msg_type.value)
    
    # TTL
    packet.append(7)
    
    # Timestamp
    timestamp_ms = int(time.time() * 1000)
    packet.extend(struct.pack('>Q', timestamp_ms))
    
    # Flags
    flags = 0
    # Include recipient field if:
    # 1. A specific recipient is provided (targeted message), OR  
    # 2. This is a message type that uses broadcast recipient (not fragments)
    exclude_recipient_types = [MessageType.FRAGMENT_START, MessageType.FRAGMENT_CONTINUE, MessageType.FRAGMENT_END]
    if recipient_id is not None or msg_type not in exclude_recipient_types:
        flags |= FLAG_HAS_RECIPIENT
    if signature:
        flags |= FLAG_HAS_SIGNATURE
    packet.append(flags)
    
    # Payload length
    packet.extend(struct.pack('>H', len(payload)))
    
    # Sender ID (exactly 8 bytes, padded with zeros if needed)
    sender_bytes = bytes.fromhex(sender_id)
    packet.extend(sender_bytes[:8])  # Take first 8 bytes
    if len(sender_bytes) < 8:
        packet.extend(bytes(8 - len(sender_bytes)))  # Pad with zeros
    
    # Recipient ID (exactly 8 bytes if present)
    if flags & FLAG_HAS_RECIPIENT:
        if recipient_id:
            recipient_bytes = bytes.fromhex(recipient_id)
            packet.extend(recipient_bytes[:8])  # Take first 8 bytes
            if len(recipient_bytes) < 8:
                packet.extend(bytes(8 - len(recipient_bytes)))  # Pad with zeros
        else:
            packet.extend(BROADCAST_RECIPIENT)
    
    # Payload
    packet.extend(payload)
    
    # Signature
    if signature:
        packet.extend(signature)
    
    # Apply iOS-style padding to standard block sizes for traffic analysis resistance
    # iOS pads ALL packets to 256 bytes for consistent BLE transmission
    block_sizes = [256, 512, 1024, 2048]
    # Account for encryption overhead (~16 bytes for AES-GCM tag)
    total_size = len(packet) + 16
    
    # Find smallest block that fits
    target_size = None
    for block_size in block_sizes:
        if total_size <= block_size:
            target_size = block_size
            break
    
    if target_size is None:
        # For very large messages, just use the original size (will be fragmented anyway)
        target_size = len(packet)
    
    padding_needed = target_size - len(packet)
    
    # PKCS#7 only supports padding up to 255 bytes
    # If we need more padding than that, don't pad - return original data
    if 0 < padding_needed <= 255:
        # iOS-style PKCS#7 padding: random bytes + padding length as last byte
        padding = bytearray(os.urandom(padding_needed - 1))
        padding.append(padding_needed)
        packet.extend(padding)

    # Add hex logging to match iOS format
    final_packet = bytes(packet)
    hex_string = ' '.join(f'{b:02X}' for b in final_packet)
    debug_full_println(f"[RAW SEND] {hex_string}")
    
    return final_packet

def create_bitchat_message_payload_full(sender: str, content: str, channel: Optional[str],
                                      is_private: bool, sender_peer_id: str, is_encrypted: bool, encrypted_content: Optional[bytes]) -> Tuple[bytes, str]:
    """Create message payload with all fields, matching Swift implementation"""
    data = bytearray()
    message_id = str(uuid.uuid4())

    # 1. Flags
    flags = 0
    if is_private: flags |= MSG_FLAG_IS_PRIVATE
    if sender_peer_id: flags |= MSG_FLAG_HAS_SENDER_PEER_ID
    if channel: flags |= MSG_FLAG_HAS_CHANNEL
    if is_encrypted: flags |= MSG_FLAG_IS_ENCRYPTED
    data.append(flags)

    # 2. Timestamp
    timestamp_ms = int(time.time() * 1000)
    data.extend(struct.pack('>Q', timestamp_ms))

    # 3. ID
    id_bytes = message_id.encode('utf-8')
    data.append(len(id_bytes))
    data.extend(id_bytes)

    # 4. Sender
    sender_bytes = sender.encode('utf-8')
    data.append(len(sender_bytes))
    data.extend(sender_bytes)

    # 5. Content
    payload_bytes = encrypted_content if is_encrypted and encrypted_content else content.encode('utf-8')
    data.extend(struct.pack('>H', len(payload_bytes)))
    data.extend(payload_bytes)

    # 6. Sender Peer ID
    if sender_peer_id:
        peer_id_bytes = sender_peer_id.encode('utf-8')
        data.append(len(peer_id_bytes))
        data.extend(peer_id_bytes)

    # 7. Channel
    if channel:
        channel_bytes = channel.encode('utf-8')
        data.append(len(channel_bytes))
        data.extend(channel_bytes)

    return (bytes(data), message_id)


    
    return (bytes(data), message_id)

def unpad_message(data: bytes) -> bytes:
    """Remove PKCS#7 padding"""
    if not data:
        return data
    
    padding_length = data[-1]
    
    if padding_length == 0 or padding_length > len(data) or padding_length > 255:
        return data
    
    return data[:-padding_length]

def create_encrypted_channel_message_payload(sender: str, content: str, channel: str, key: bytes, encryption_service, sender_peer_id: str) -> Tuple[bytes, str]:
    """Create encrypted channel message payload"""
    encrypted_content = encryption_service.encrypt_with_key(content.encode(), key)
    return create_bitchat_message_payload_full(sender, content, channel, False, sender_peer_id, True, encrypted_content)

def should_fragment(packet: bytes) -> bool:
    """Check if packet needs fragmentation"""
    return len(packet) > 500

def should_send_ack(is_private: bool, channel: Optional[str], mentions: Optional[List[str]],
                   my_nickname: str, active_peer_count: int) -> bool:
    """Determine if we should send an ACK"""
    if is_private:
        return True
    elif channel:
        if active_peer_count < 10:
            return True
        elif mentions and my_nickname in mentions:
            return True
    return False

async def main():
    """Main entry point"""
    client = BitchatClient()
    await client.run()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[+] Exiting...")