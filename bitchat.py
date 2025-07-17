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

from encryption import EncryptionService, EncryptionError
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
        print(*args, **kwargs)

def debug_full_println(*args, **kwargs):
    if DEBUG_LEVEL >= DebugLevel.FULL:
        print(*args, **kwargs)

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
        
        # Clear encryption keys (but keep our own keys)
        self.encryption_service.session_manager.sessions.clear()
        
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
        
        # If we have a connection, send key exchange and announce
        if self.client and self.characteristic:
            # Initiate handshake with all peers
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
                
                # Fallback to write without response if with response fails
                if write_with_response:
                    try:
                        await self.client.write_gatt_char(
                            self.characteristic, 
                            packet, 
                            response=False
                        )
                    except Exception as e2:
                        if "not connected" in str(e2).lower():
                            debug_println("[!] Lost connection while sending")
                            if self.client:
                                self.handle_disconnect(self.client)
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
        debug_full_println(f"[RAW RECV] {data.hex()}")
        try:
            packet = parse_bitchat_packet(data)
            
            # Ignore our own messages (they are already displayed when sent)
            if packet.sender_id_str == self.my_peer_id:
                return
            
            await self.handle_packet(packet, data)
            
        except Exception as e:
            debug_full_println(f"[ERROR] Failed to parse packet: {e}")
    
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
            
            # Always send key exchange to new peer
            debug_println(f"[CRYPTO] Sending key exchange to new peer {packet.sender_id_str}")
            key_exchange_payload = self.encryption_service.get_combined_public_key_data()
            key_exchange_packet = create_bitchat_packet(
                self.my_peer_id, MessageType.KEY_EXCHANGE, key_exchange_payload
            )
            await self.send_packet(key_exchange_packet)
    
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
        
        # Handle private message decryption
        is_private_message = not is_broadcast and is_for_us
        decrypted_payload = None
        
        if is_private_message:
            try:
                decrypted_payload = self.encryption_service.decrypt_from_peer(packet.sender_id_str, packet.payload)
                debug_println("[PRIVATE] Successfully decrypted private message!")
            except EncryptionError:
                debug_println("[PRIVATE] Failed to decrypt private message")
                return
        
        # Parse message
        try:
            if is_private_message and decrypted_payload:
                unpadded = unpad_message(decrypted_payload)
                message = parse_bitchat_message_payload(unpadded)
            else:
                message = parse_bitchat_message_payload(packet.payload)
            
            # Check for duplicates using both bloom filter and set
            if message.id not in self.processed_messages and 1==0:
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
            response = self.encryption_service.handle_handshake_message(packet.sender_id_str, packet.payload)
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
            identity_data = json.loads(packet.payload)
            peer_id = identity_data.get('peerID')
            nickname = identity_data.get('nickname')
            public_key_b64 = identity_data.get('publicKey')

            if peer_id and nickname and public_key_b64:
                is_new_peer = peer_id not in self.peers
                if is_new_peer:
                    self.peers[peer_id] = Peer()
                self.peers[peer_id].nickname = nickname

                if is_new_peer:
                    print(f"\r\u001b[K\u001b[33m{nickname} connected\u001b[0m\n> ", end='', flush=True)
                    debug_println(f"[<-- RECV] Announce: Peer {peer_id} is now known as '{nickname}'")

                    # Initiate handshake
                    handshake_message = self.encryption_service.initiate_handshake(peer_id)
                    handshake_packet = create_bitchat_packet(
                        self.my_peer_id, MessageType.KEY_EXCHANGE, handshake_message
                    )
                    await self.send_packet(handshake_packet)

        except Exception as e:
            debug_println(f"[ERROR] Failed to parse noise identity announcement: {e}")
    
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
            
            print("\n╭─── Connection Status ───╮")
            print(f"│ Status: {connection_status:^15} │")
            print(f"│ Peers connected: {peer_count:3}    │")
            print(f"│ Active channels: {channel_count:3}    │")
            print(f"│ Active DMs:      {dm_count:3}    │")
            print("│                         │")
            print(f"│ Your nickname: {self.nickname[:9]:^9}│")
            print(f"│ Your ID: {self.my_peer_id[:8]}...│")
            print("╰─────────────────────────╯")
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
    
    async def send_private_message(self, content: str, target_peer_id: str, target_nickname: str):
        """Send a private encrypted message"""
        if not self.client or not self.characteristic:
            print("\033[93m⚠ Not connected to any peers yet.\033[0m")
            return

        if not self.encryption_service.is_session_established(target_peer_id):
            print(f"\033[93m⚠ Secure session with {target_nickname} not established yet.\033[0m")
            print(f"\033[90mWait for the handshake to complete (usually takes a few seconds after they connect).\033[0m")
            return
            
        debug_println(f"[PRIVATE] Sending encrypted message to {target_nickname}")
        
        # Create message payload
        payload, message_id = create_bitchat_message_payload_full(
            self.nickname, content, None, True, self.my_peer_id, True, None
        )
        
        # Track for delivery
        self.delivery_tracker.track_message(message_id, content, True)
        
        # Pad message
        block_sizes = [256, 512, 1024, 2048]
        target_size = next((size for size in block_sizes if len(payload) + 16 <= size), len(payload))
        padding_needed = target_size - len(payload)
        
        padded_payload = bytearray(payload)
        if 0 < padding_needed <= 255:
            padded_payload.extend([padding_needed] * padding_needed)
            debug_println(f"[PRIVATE] Added {padding_needed} bytes of PKCS#7 padding")
        
        try:
            encrypted = self.encryption_service.encrypt_for_peer(target_peer_id, bytes(padded_payload))
            debug_println(f"[PRIVATE] Encrypted payload: {len(encrypted)} bytes")
            
            # Create packet
            packet = create_bitchat_packet_with_recipient(
                self.my_peer_id,
                target_peer_id,
                MessageType.MESSAGE,
                encrypted,
                None
            )
            
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
            
        except Exception as e:
            print(f"[!] Failed to encrypt private message: {e}")
            print(f"[!] Make sure you have received key exchange from {target_nickname}")
    
    async def background_scanner(self):
        """Background task to scan for peers when not connected"""
        while self.running:
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
                            
                            # Send handshake
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

def parse_bitchat_packet(data: bytes) -> BitchatPacket:
    """Parse a BitChat packet from raw bytes"""
    HEADER_SIZE = 13
    SENDER_ID_SIZE = 8
    RECIPIENT_ID_SIZE = 8
    
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
    
    # Sender ID
    sender_id = data[offset:offset+SENDER_ID_SIZE]
    sender_id_str = sender_id.hex()
    offset += SENDER_ID_SIZE
    
    # Recipient ID
    recipient_id = None
    recipient_id_str = None
    if has_recipient:
        recipient_id = data[offset:offset+RECIPIENT_ID_SIZE]
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
    has_recipient = msg_type not in [MessageType.FRAGMENT_START, MessageType.FRAGMENT_CONTINUE, MessageType.FRAGMENT_END]
    if has_recipient:
        flags |= FLAG_HAS_RECIPIENT
    if signature:
        flags |= FLAG_HAS_SIGNATURE
    packet.append(flags)
    
    # Payload length
    packet.extend(struct.pack('>H', len(payload)))
    
    # Sender ID
    sender_bytes = bytes.fromhex(sender_id)
    packet.extend(sender_bytes)
    
    # Recipient ID
    if has_recipient:
        if recipient_id:
            recipient_bytes = bytes.fromhex(recipient_id)
            packet.extend(recipient_bytes)
        else:
            packet.extend(BROADCAST_RECIPIENT)
    
    # Payload
    packet.extend(payload)
    
    # Signature
    if signature:
        packet.extend(signature)
    
    # Pad to standard block size
    block_sizes = [256, 512, 1024, 2048]
    target_size = next((size for size in block_sizes if len(packet) + 16 <= size), len(packet))
    padding_needed = target_size - len(packet)
    if 0 < padding_needed <= 255:
        padding = bytes([padding_needed] * padding_needed)
        packet.extend(padding)

    return bytes(packet)

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