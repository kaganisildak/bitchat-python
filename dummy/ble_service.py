"""
Bluetooth Low Energy Service for BitChat
Handles BLE scanning, connections, and mesh networking.
Compatible with Swift BluetoothMeshService implementation.
"""

import asyncio
import json
import secrets
import time
from typing import Dict, List, Optional, Callable, Set
from dataclasses import dataclass

from bleak import BleakScanner, BleakClient
from bleak.backends.device import BLEDevice
from bleak.backends.characteristic import BleakGATTCharacteristic

from protocol import (
    BitchatPacket, BitchatMessage, MessageType, VersionHello, VersionAck,
    BLE_SERVICE_UUID, BLE_CHARACTERISTIC_UUID, BROADCAST_RECIPIENT, CURRENT_VERSION, SUPPORTED_VERSIONS
)
from encryption import EncryptionService
from compression_util import CompressionUtil

@dataclass
class PeerInfo:
    """Information about a discovered peer"""
    peer_id: str
    nickname: str
    device: BLEDevice
    client: Optional[BleakClient] = None
    last_seen: float = 0
    rssi: int = -999
    announced: bool = False

class BitchatBLEService:
    """
    Bluetooth Low Energy service for BitChat mesh networking.
    Handles device discovery, connections, and message routing.
    """
    
    def __init__(self, nickname: str, encryption_service: EncryptionService):
        self.nickname = nickname
        self.encryption_service = encryption_service
        self.compression_util = CompressionUtil()
        
        # Generate ephemeral peer ID matching Swift format (16 hex chars)
        self.my_peer_id = secrets.token_hex(8)  # 8 bytes = 16 hex chars
        
        # Connection tracking
        self.connected_clients: Dict[str, BleakClient] = {}
        self.peers: Dict[str, PeerInfo] = {}
        self.peer_nicknames: Dict[str, str] = {}  # Add this missing attribute
        self.running = False
        
        # Message processing
        self.processed_messages: Set[str] = set()
        self.max_processed_messages = 1000
        
        # Timing
        self.last_announce_time = 0.0
        self.announce_interval = 30.0  # seconds
        
        # Callbacks
        self.on_message_received: Optional[Callable] = None
        self.on_peer_connected: Optional[Callable] = None
        self.on_peer_discovered: Optional[Callable] = None
        
        # Tasks
        self.discovery_task = None
        self.message_processor_task = None
        self.cleanup_task = None
        
        # Setup encryption callbacks
        self.encryption_service.on_peer_authenticated = self._on_peer_authenticated
        self.encryption_service.on_handshake_required = self._on_handshake_required
    
    async def start(self):
        """Start the BLE service"""
        if self.running:
            return
        
        self.running = True
        print(f"Starting BitChat BLE service with peer ID: {self.my_peer_id}")
        
        # Start background tasks
        self.discovery_task = asyncio.create_task(self._discovery_loop())
        self.message_processor_task = asyncio.create_task(self._message_processor())
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())
        
        # Start advertising (act as peripheral)
        self.advertise_task = asyncio.create_task(self._advertising_loop())
        
        # Send initial announce and identity announcement after short delay
        await asyncio.sleep(2.0)
        await self._send_announce()
        await self._send_noise_identity_announce()
    
    async def stop(self):
        """Stop the BLE service"""
        if not self.running:
            return
        
        self.running = False
        print("Stopping BitChat BLE service")
        
        # Cancel tasks
        if self.discovery_task:
            self.discovery_task.cancel()
        if self.message_processor_task:
            self.message_processor_task.cancel()
        if self.cleanup_task:
            self.cleanup_task.cancel()
        if hasattr(self, 'advertise_task') and self.advertise_task:
            self.advertise_task.cancel()
        
        # Disconnect from all peers
        for client in list(self.connected_clients.values()):
            try:
                await client.disconnect()
            except Exception:
                pass
        
        self.connected_clients.clear()
        self.peers.clear()
    
    async def _discovery_loop(self):
        """Continuously scan for BitChat devices"""
        while self.running:
            try:
                print("Scanning for BitChat devices...")
                
                # Use callback-based scanning to get RSSI and advertisement data
                discovered_devices = {}
                
                def detection_callback(device: BLEDevice, advertisement_data):
                    # Store device with RSSI from advertisement data
                    discovered_devices[device.address] = (device, advertisement_data.rssi)
                
                # Start callback-based scanning
                scanner = BleakScanner(detection_callback, service_uuids=[BLE_SERVICE_UUID])
                await scanner.start()
                await asyncio.sleep(10.0)  # Scan for 10 seconds
                await scanner.stop()
                
                # Process discovered devices
                for device, rssi in discovered_devices.values():
                    await self._handle_discovered_device_with_rssi(device, rssi)
                
                # Small delay before next scan
                await asyncio.sleep(5.0)
                
            except Exception as e:
                print(f"Error during discovery: {e}")
                # Fallback to basic discovery
                try:
                    devices = await BleakScanner.discover(
                        service_uuids=[BLE_SERVICE_UUID],
                        timeout=5.0
                    )
                    for device in devices:
                        await self._handle_discovered_device(device)
                except Exception as fallback_error:
                    print(f"Fallback discovery also failed: {fallback_error}")
                
                await asyncio.sleep(10.0)
    
    async def _advertising_loop(self):
        """Advertise as a BitChat peripheral using device name"""
        while self.running:
            try:
                print(f">> Advertising as BitChat service with ID: {self.my_peer_id}")
                # Note: bleak doesn't support peripheral mode advertising on most platforms
                # This is a limitation - we can only act as central (scanner)
                # For full bidirectional communication, we'd need platform-specific code
                await asyncio.sleep(30.0)  # Placeholder - check every 30 seconds
                
            except Exception as e:
                print(f"Error in advertising loop: {e}")
                await asyncio.sleep(10.0)
    
    async def _handle_discovered_device(self, device: BLEDevice):
        """Handle a newly discovered device"""
        # Extract peer ID from device name if available
        peer_id = device.name or device.address
        
        # Skip if it's ourselves (shouldn't happen but safety check)
        if peer_id == self.my_peer_id:
            return
        
        # Check if already connected
        if peer_id in self.connected_clients:
            return
        
        # Get RSSI safely - it may not be available in basic discovery
        rssi = getattr(device, 'rssi', None) or -999
        
        print(f"Discovered device: {device.name} ({device.address}) RSSI: {rssi}")
        
        # Store peer info
        peer_info = PeerInfo(
            peer_id=peer_id,
            nickname="",  # Will be filled from announce message
            device=device,
            last_seen=time.time(),
            rssi=rssi
        )
        self.peers[peer_id] = peer_info
        
        # Attempt connection
        await self._connect_to_peer(device, peer_id)
    
    async def _handle_discovered_device_with_rssi(self, device: BLEDevice, rssi: int):
        """Handle a discovered device with RSSI information"""
        # Extract peer ID from device name if available
        peer_id = device.name or device.address
        
        # Skip if it's ourselves (shouldn't happen but safety check)
        if peer_id == self.my_peer_id:
            return
        
        # Check if already connected
        if peer_id in self.connected_clients:
            return
        
        print(f"Discovered device: {device.name} ({device.address}) RSSI: {rssi}")
        
        # Store peer info with accurate RSSI
        peer_info = PeerInfo(
            peer_id=peer_id,
            nickname="",  # Will be filled from announce message
            device=device,
            last_seen=time.time(),
            rssi=rssi
        )
        self.peers[peer_id] = peer_info
        
        # Attempt connection
        await self._connect_to_peer(device, peer_id)
    
    async def _connect_to_peer(self, device: BLEDevice, peer_id: str):
        """Connect to a peer device"""
        try:
            print(f"Connecting to {device.name or 'Unknown'}...")
            client = BleakClient(device.address)
            await client.connect()
            print(f"Connected to {device.name or 'Unknown'}")
            print(f"Client connected status: {client.is_connected}")
            
            if not client.is_connected:
                print(f"Failed to establish connection to {device.name}")
                return
            
            # Get peer ID from device name (16 hex chars)
            peer_id = device.name if device.name and len(device.name) == 16 else "Unknown"
            
            # Store the connection - REMOVED: Will be added in _setup_notifications after successful setup
            # self.connected_clients[peer_id] = client
            
            # Subscribe to notifications
            await self._setup_notifications(peer_id, client)
            
            # Send version hello
            # await self._send_version_hello(client)
            
        except Exception as e:
            print(f"Error connecting to {device.address}: {e}")
            try:
                if 'client' in locals() and client.is_connected:
                    await client.disconnect()
            except:
                pass
    
    async def _setup_notifications(self, peer_id: str, client: BleakClient):
        """Setup notifications for a connected peer"""
        try:
            print(f"🔧 Setting up notifications for {peer_id}")
            
            # Wait for service discovery to complete
            await asyncio.sleep(1.0)
            
            # Debug: Check services for BitChat
            print(f"Discovering services for {peer_id}...")
            
            # Find our characteristic using the services property
            target_service_uuid = BLE_SERVICE_UUID.lower()
            target_char_uuid = BLE_CHARACTERISTIC_UUID.lower()
            
            for service in client.services:
                service_uuid = str(service.uuid).lower()
                if service_uuid == target_service_uuid:
                    for char in service.characteristics:
                        char_uuid = str(char.uuid).lower()
                        if char_uuid == target_char_uuid:
                            print(f"Found BitChat characteristic on {peer_id}")
                            # Start notifications with error handling
                            try:
                                await client.start_notify(char, 
                                    lambda sender, data, p=peer_id: asyncio.create_task(
                                        self._on_data_received(p, data)
                                    ))
                                print(f"Subscribed to notifications from {peer_id}")
                                
                                # CRITICAL: Add to connected_clients here after successful notification setup
                                self.connected_clients[peer_id] = client
                                print(f"✅ Added {peer_id} to connected_clients")
                                print(f"  Connected clients now: {list(self.connected_clients.keys())}")
                                
                                # Send announce and identity announcement after subscribing 
                                await asyncio.sleep(0.5)  # Small delay
                                await self._send_announce()
                                await self._send_noise_identity_announce()
                                
                            except Exception as e:
                                print(f"Warning: Could not setup notifications for {peer_id}: {e}")
                                # Continue without notifications - we can still send messages
                            return
            
            print(f"BitChat characteristic not found on {peer_id}")
            print(f"Looking for service: {BLE_SERVICE_UUID}")
            print(f"Looking for characteristic: {BLE_CHARACTERISTIC_UUID}")
            
        except Exception as e:
            print(f"Error setting up notifications for {peer_id}: {e}")
            import traceback
            traceback.print_exc()
    
    async def _on_data_received(self, peer_id: str, data: bytes):
        """Handle received data from a peer"""
        try:
            print(f"\n=== RAW PACKET RECEIVED ===")
            print(f"From: {peer_id}")
            print(f"Size: {len(data)} bytes")
            print(f"Raw hex: {data.hex()}")
            print(f"Raw bytes: {list(data[:20])}{'...' if len(data) > 20 else ''}")
            
            # Decode packet
            packet = BitchatPacket.from_binary(data, self.compression_util)
            if not packet:
                print(f"❌ Failed to decode packet from {peer_id}")
                return
            
            print(f"✅ Decoded packet:")
            print(f"  Type: {packet.message_type} ({MessageType(packet.message_type).name if packet.message_type in [m.value for m in MessageType] else 'UNKNOWN'})")
            print(f"  TTL: {packet.ttl}")
            print(f"  Sender: {packet.get_sender_hex()}")
            print(f"  Recipient: {packet.get_recipient_hex()}")
            print(f"  Payload size: {len(packet.payload)} bytes")
            print(f"  Payload preview: {packet.payload[:50]}{'...' if len(packet.payload) > 50 else ''}")
            print(f"=== END PACKET ===\n")
            
            # Update peer last seen
            if peer_id in self.peers:
                self.peers[peer_id].last_seen = time.time()
            
            # Handle the packet
            await self._handle_received_packet(packet, peer_id)
            
        except Exception as e:
            print(f"❌ Error processing data from {peer_id}: {e}")
            import traceback
            traceback.print_exc()
    
    async def _handle_received_packet(self, packet: BitchatPacket, from_peer: str):
        """Handle a received packet"""
        # Check TTL
        if packet.ttl == 0:
            return
        
        # Generate message ID for duplicate detection
        # Convert payload to bytes if it's a bytearray to make it hashable
        payload_for_hash = bytes(packet.payload) if isinstance(packet.payload, bytearray) else packet.payload
        message_id = f"{packet.timestamp}-{packet.get_sender_hex()}-{hash(payload_for_hash)}"
        
        # Check for duplicates
        if message_id in self.processed_messages:
            return
        
        # Add to processed set
        self.processed_messages.add(message_id)
        
        # Cleanup old processed messages
        if len(self.processed_messages) > self.max_processed_messages:
            # Remove oldest 100 entries (simple cleanup)
            for _ in range(100):
                self.processed_messages.pop()
        
        # Handle by message type
        if packet.message_type == MessageType.ANNOUNCE:
            await self._handle_announce(packet, from_peer)
        
        elif packet.message_type == MessageType.MESSAGE:
            await self._handle_message(packet, from_peer)
        
        elif packet.message_type == MessageType.VERSION_HELLO:
            await self._handle_version_hello(packet, from_peer)
        
        elif packet.message_type == MessageType.VERSION_ACK:
            await self._handle_version_ack(packet, from_peer)
        
        elif packet.message_type == MessageType.NOISE_HANDSHAKE_INIT:
            await self._handle_noise_handshake_init(packet, from_peer)
        
        elif packet.message_type == MessageType.NOISE_HANDSHAKE_RESP:
            await self._handle_noise_handshake_resp(packet, from_peer)
        
        elif packet.message_type == MessageType.NOISE_ENCRYPTED:
            await self._handle_noise_encrypted(packet, from_peer)
        
        elif packet.message_type == MessageType.NOISE_IDENTITY_ANNOUNCE:
            await self._handle_noise_identity_announce(packet, from_peer)
        
        else:
            print(f"Unhandled packet type {packet.message_type} from {from_peer}")
        
        # Relay packet if needed (decrease TTL)
        if packet.ttl > 1:
            await self._relay_packet(packet)
    
    async def _handle_announce(self, packet: BitchatPacket, from_peer: str):
        """Handle announce message"""
        try:
            nickname = packet.payload.decode('utf-8')
            sender_id = packet.get_sender_hex()
            
            print(f"Peer {sender_id} announced as '{nickname}'")
            
            # Update peer info in both dictionaries
            self.peer_nicknames[sender_id] = nickname
            
            if sender_id in self.peers:
                self.peers[sender_id].nickname = nickname
                self.peers[sender_id].announced = True
            else:
                # Create new peer info
                self.peers[sender_id] = PeerInfo(
                    peer_id=sender_id,
                    nickname=nickname,
                    device=None,  # We don't have device info
                    last_seen=time.time(),
                    announced=True
                )
            
            print(f"Updated peer tracking: {sender_id} -> {nickname}")
            print(f"Available peers for DM: {list(self.peer_nicknames.values())}")
            
            # Notify callback
            if self.on_peer_discovered:
                asyncio.create_task(self.on_peer_discovered(sender_id, nickname))
                
        except Exception as e:
            print(f"Error handling announce: {e}")
            import traceback
            traceback.print_exc()
    
    async def _handle_message(self, packet: BitchatPacket, from_peer: str):
        """Handle regular message"""
        try:
            # Check if it's a broadcast or private message
            is_broadcast = (packet.recipient_id == BROADCAST_RECIPIENT)
            is_for_us = (packet.get_recipient_hex() == self.my_peer_id)
            
            if is_broadcast or is_for_us:
                # Parse message
                message = BitchatMessage.from_binary_payload(packet.payload)
                if message:
                    # Update sender tracking
                    sender_id = packet.get_sender_hex()
                    sender_nickname = message.sender
                    
                    # Check if this is a new peer
                    is_new_peer = sender_id not in self.peer_nicknames
                    
                    # Always update peer tracking when we receive messages
                    self.peer_nicknames[sender_id] = sender_nickname
                    
                    if sender_id in self.peers:
                        self.peers[sender_id].nickname = sender_nickname
                        self.peers[sender_id].last_seen = time.time()
                    else:
                        # Create new peer info from message
                        self.peers[sender_id] = PeerInfo(
                            peer_id=sender_id,
                            nickname=sender_nickname,
                            device=None,
                            last_seen=time.time(),
                            announced=True
                        )
                    
                    # Notify about new peer discovery
                    if is_new_peer and self.on_peer_discovered:
                        print(f"Discovered new peer through message: {sender_id} ({sender_nickname})")
                        asyncio.create_task(self.on_peer_discovered(sender_id, sender_nickname))
                    
                    # Update message with correct sender info if we have better data
                    if sender_id in self.peers:
                        # Create updated message with correct sender info
                        message = BitchatMessage(
                            id=message.id,
                            sender=self.peers[sender_id].nickname,
                            content=message.content,
                            timestamp=message.timestamp,
                            is_private=message.is_private,
                            sender_peer_id=sender_id,
                            channel=message.channel,
                            recipient_nickname=self.nickname if message.is_private else message.recipient_nickname,
                            is_relay=message.is_relay,
                            original_sender=message.original_sender
                        )
                    
                    # Display message in console
                    if message.is_private:
                        print(f"[DM from {message.sender}] {message.content}")
                    else:
                        print(f"[{message.sender}] {message.content}")
                    
                    # Notify callback
                    if self.on_message_received:
                        asyncio.create_task(self.on_message_received(message))
        
        except Exception as e:
            print(f"Error handling message: {e}")
            import traceback
            traceback.print_exc()
    
    async def _handle_version_hello(self, packet: BitchatPacket, from_peer: str):
        """Handle version negotiation hello"""
        try:
            hello = VersionHello.decode(packet.payload)
            if hello:
                print(f"Version hello from {from_peer}: {hello.client_version} on {hello.platform}")
                
                # Send version ack
                ack = VersionAck(
                    agreed_version=CURRENT_VERSION,
                    client_version="1.0.0-python",
                    platform="Python"
                )
                
                await self._send_packet_to_peer(BitchatPacket(
                    message_type=MessageType.VERSION_ACK,
                    sender_id=bytes.fromhex(self.my_peer_id),
                    recipient_id=bytes.fromhex(packet.get_sender_hex()),
                    payload=ack.encode(),
                    ttl=1
                ), from_peer)
                
        except Exception as e:
            print(f"Error handling version hello: {e}")
    
    async def _handle_version_ack(self, packet: BitchatPacket, from_peer: str):
        """Handle version negotiation ack"""
        try:
            ack = VersionAck.decode(packet.payload)
            if ack:
                print(f"Version ack from {from_peer}: agreed on version {ack.agreed_version}")
                
        except Exception as e:
            print(f"Error handling version ack: {e}")
    
    async def _handle_noise_handshake_init(self, packet: BitchatPacket, from_peer: str):
        """Handle Noise handshake initiation"""
        try:
            sender_id = packet.get_sender_hex()
            # Convert bytearray to bytes for encryption service
            payload_bytes = bytes(packet.payload) if isinstance(packet.payload, bytearray) else packet.payload
            response = self.encryption_service.process_handshake_message(sender_id, payload_bytes)
            
            if response:
                # Send handshake response
                response_packet = BitchatPacket(
                    message_type=MessageType.NOISE_HANDSHAKE_RESP,
                    sender_id=bytes.fromhex(self.my_peer_id),
                    recipient_id=packet.sender_id,
                    payload=response,
                    ttl=1
                )
                
                await self._send_packet_to_peer(response_packet, from_peer)
                
        except Exception as e:
            print(f"Error handling Noise handshake init: {e}")
    
    async def _handle_noise_handshake_resp(self, packet: BitchatPacket, from_peer: str):
        """Handle Noise handshake response"""
        try:
            sender_id = packet.get_sender_hex()
            # Convert bytearray to bytes for encryption service
            payload_bytes = bytes(packet.payload) if isinstance(packet.payload, bytearray) else packet.payload
            response = self.encryption_service.process_handshake_message(sender_id, payload_bytes)
            
            if response:
                # Send final handshake message
                final_packet = BitchatPacket(
                    message_type=MessageType.NOISE_HANDSHAKE_INIT,  # Continue with same type
                    sender_id=bytes.fromhex(self.my_peer_id),
                    recipient_id=packet.sender_id,
                    payload=response,
                    ttl=1
                )
                
                await self._send_packet_to_peer(final_packet, from_peer)
                
        except Exception as e:
            print(f"Error handling Noise handshake response: {e}")
    
    async def _handle_noise_encrypted(self, packet: BitchatPacket, from_peer: str):
        """Handle Noise encrypted message"""
        try:
            sender_id = packet.get_sender_hex()
            # Convert bytearray to bytes for encryption service
            payload_bytes = bytes(packet.payload) if isinstance(packet.payload, bytearray) else packet.payload
            decrypted = self.encryption_service.decrypt(payload_bytes, sender_id)
            
            # Parse inner packet
            inner_packet = BitchatPacket.from_binary(decrypted, self.compression_util)
            if inner_packet:
                await self._handle_received_packet(inner_packet, from_peer)
                
        except Exception as e:
            print(f"Error handling Noise encrypted message: {e}")
    
    async def _handle_noise_identity_announce(self, packet: BitchatPacket, from_peer: str):
        """Handle Noise identity announcement"""
        try:
            sender_id = packet.get_sender_hex()
            print(f"Received Noise identity announcement from {sender_id}")
            
            # Try to decode the identity announcement
            try:
                announcement_data = json.loads(packet.payload.decode('utf-8'))
                peer_id = announcement_data.get('peerID', sender_id)
                nickname = announcement_data.get('nickname', 'Unknown')
                
                print(f"Identity announcement: {peer_id} -> {nickname}")
                
                # Check if this is a new peer
                is_new_peer = peer_id not in self.peer_nicknames
                
                # Update peer info - THIS IS THE CRITICAL FIX
                self.peer_nicknames[peer_id] = nickname
                
                if peer_id in self.peers:
                    self.peers[peer_id].nickname = nickname
                    self.peers[peer_id].last_seen = time.time()
                else:
                    # Create new peer info
                    self.peers[peer_id] = PeerInfo(
                        peer_id=peer_id,
                        nickname=nickname,
                        device=None,
                        last_seen=time.time(),
                        announced=True
                    )
                
                print(f"Updated peer tracking from identity: {peer_id} -> {nickname}")
                print(f"Available peers for DM: {list(self.peer_nicknames.values())}")
                
                # Notify about new peer discovery
                if is_new_peer and self.on_peer_discovered:
                    print(f"Discovered new peer through identity announcement: {peer_id} ({nickname})")
                    asyncio.create_task(self.on_peer_discovered(peer_id, nickname))
                
                # Check if we should initiate handshake (lexicographic comparison)
                if self.my_peer_id < peer_id:
                    print(f"We should initiate handshake with {peer_id}")
                    await self._initiate_noise_handshake(peer_id)
                else:
                    print(f"Waiting for {peer_id} to initiate handshake")
                    # Send our own identity announcement
                    await self._send_noise_identity_announce()
                    
            except json.JSONDecodeError:
                print(f"Could not decode identity announcement from {sender_id}")
                
        except Exception as e:
            print(f"Error handling Noise identity announcement: {e}")
            import traceback
            traceback.print_exc()
    
    async def _send_noise_identity_announce(self):
        """Send our Noise identity announcement"""
        try:
            # Get our static public key from encryption service
            fingerprint = self.encryption_service.get_identity_fingerprint()
            
            announcement = {
                "peerID": self.my_peer_id,
                "nickname": self.nickname,
                "publicKey": fingerprint[:32],  # Use part of fingerprint as placeholder
                "timestamp": time.time(),
                "previousPeerID": None,
                "signature": fingerprint[32:64] if len(fingerprint) >= 64 else "00" * 32
            }
            
            payload = json.dumps(announcement).encode('utf-8')
            
            packet = BitchatPacket(
                message_type=MessageType.NOISE_IDENTITY_ANNOUNCE,
                sender_id=bytes.fromhex(self.my_peer_id),
                payload=payload,
                ttl=6  # High TTL like Swift
            )
            
            await self._broadcast_packet(packet)
            print(f"Sent Noise identity announcement for {self.my_peer_id}")
            
        except Exception as e:
            print(f"Error sending identity announcement: {e}")
    
    async def _initiate_noise_handshake(self, peer_id: str):
        """Initiate Noise handshake with a peer"""
        try:
            # Create handshake initiation
            handshake_data = self.encryption_service.initiate_handshake(peer_id)
            
            packet = BitchatPacket(
                message_type=MessageType.NOISE_HANDSHAKE_INIT,
                sender_id=bytes.fromhex(self.my_peer_id),
                recipient_id=bytes.fromhex(peer_id),
                payload=handshake_data,
                ttl=1
            )
            
            await self._send_packet_to_peer(packet, peer_id)
            print(f"Initiated Noise handshake with {peer_id}")
            
        except Exception as e:
            print(f"Error initiating handshake with {peer_id}: {e}")
    
    async def _send_version_hello(self, client: BleakClient):
        """Send version negotiation hello"""
        try:
            hello = VersionHello(
                supported_versions=SUPPORTED_VERSIONS,
                preferred_version=CURRENT_VERSION,
                client_version="1.0.0-python",
                platform="Python"
            )
            
            packet = BitchatPacket(
                message_type=MessageType.VERSION_HELLO,
                sender_id=bytes.fromhex(self.my_peer_id),
                payload=hello.encode(),
                ttl=1
            )
            
            await self._send_packet_to_client(packet, client)
            
        except Exception as e:
            print(f"Error sending version hello: {e}")
    
    async def _send_announce(self):
        """Send announce message to all connected peers (matching Swift implementation)"""
        current_time = time.time()
        
        # Rate limit announces
        if current_time - self.last_announce_time < self.announce_interval:
            return
        
        self.last_announce_time = current_time
        
        packet = BitchatPacket(
            message_type=MessageType.ANNOUNCE,
            sender_id=bytes.fromhex(self.my_peer_id),
            payload=self.nickname.encode('utf-8'),
            ttl=3
        )
        
        # Send multiple times with delays like Swift implementation
        await self._broadcast_packet(packet)
        
        # Additional sends with jittered delays for reliability  
        for delay in [0.2, 0.5, 1.0]:
            jittered_delay = delay + (time.time() % 1000) / 10000  # Small jitter
            await asyncio.sleep(jittered_delay)
            if self.running:  # Check if still running
                await self._broadcast_packet(packet)
    
    async def _send_announce_to_peer(self, client: BleakClient):
        """Send announce message to a specific peer"""
        packet = BitchatPacket(
            message_type=MessageType.ANNOUNCE,
            sender_id=bytes.fromhex(self.my_peer_id),
            payload=self.nickname.encode('utf-8'),
            ttl=3
        )
        
        await self._send_packet_to_client(packet, client)
    
    async def send_message(self, content: str, channel: Optional[str] = None, 
                          recipient_peer_id: Optional[str] = None):
        """Send a message to the network"""
        try:
            print(f"\n🚀 SENDING MESSAGE:")
            print(f"  Content: '{content}'")
            print(f"  Channel: {channel}")
            print(f"  Recipient: {recipient_peer_id}")
            print(f"  Is DM: {recipient_peer_id is not None}")
            
            # Get recipient nickname for private messages
            recipient_nickname = None
            if recipient_peer_id:
                if recipient_peer_id in self.peers:
                    recipient_nickname = self.peers[recipient_peer_id].nickname
                else:
                    recipient_nickname = "Unknown"
                print(f"  Recipient nickname: {recipient_nickname}")
            
            # Create message
            message = BitchatMessage(
                id="",  # Will be auto-generated
                sender=self.nickname,
                content=content,
                timestamp=time.time(),
                is_private=recipient_peer_id is not None,
                sender_peer_id=self.my_peer_id,
                channel=channel,
                recipient_nickname=recipient_nickname
            )
            
            print(f"  Created message ID: {message.id}")
            print(f"  Message is_private: {message.is_private}")
            
            # Create packet
            recipient_id = None
            if recipient_peer_id:
                recipient_id = bytes.fromhex(recipient_peer_id)
                print(f"  Recipient ID bytes: {recipient_id.hex()}")
            else:
                recipient_id = BROADCAST_RECIPIENT
                print(f"  Broadcasting to: {recipient_id.hex()}")
            
            packet = BitchatPacket(
                message_type=MessageType.MESSAGE,
                sender_id=bytes.fromhex(self.my_peer_id),
                recipient_id=recipient_id,
                payload=message.to_binary_payload(),
                ttl=3
            )
            
            print(f"  Packet created - type: {packet.message_type}, payload size: {len(packet.payload)}")
            
            # Send packet
            if recipient_peer_id and self.encryption_service.has_established_session(recipient_peer_id):
                # Send encrypted private message
                print(f"  📡 Sending encrypted DM to {recipient_nickname} ({recipient_peer_id[:8]}...)")
                await self._send_encrypted_packet(packet, recipient_peer_id)
            elif recipient_peer_id:
                # Private message but no encryption session - send directly for now
                print(f"  📡 Sending unencrypted DM to {recipient_nickname} ({recipient_peer_id[:8]}...)")
                await self._send_packet_to_peer(packet, recipient_peer_id)
            else:
                # Send as broadcast
                print(f"  📡 Broadcasting public message")
                await self._broadcast_packet(packet)
            
            print(f"✅ Message sending completed")
            
        except Exception as e:
            print(f"❌ Error sending message: {e}")
            import traceback
            traceback.print_exc()
    
    async def _send_encrypted_packet(self, packet: BitchatPacket, peer_id: str):
        """Send an encrypted packet to a specific peer"""
        try:
            # Serialize packet
            packet_data = packet.to_binary(self.compression_util)
            
            # Encrypt with Noise
            encrypted_data = self.encryption_service.encrypt(packet_data, peer_id)
            
            # Create encrypted packet
            encrypted_packet = BitchatPacket(
                message_type=MessageType.NOISE_ENCRYPTED,
                sender_id=bytes.fromhex(self.my_peer_id),
                recipient_id=bytes.fromhex(peer_id),
                payload=encrypted_data,
                ttl=1
            )
            
            # Send to peer
            await self._send_packet_to_peer(encrypted_packet, peer_id)
            
        except Exception as e:
            print(f"Error sending encrypted packet: {e}")
    
    async def _broadcast_packet(self, packet: BitchatPacket):
        """Broadcast packet to all connected peers"""
        if not self.connected_clients:
            print("No connected clients to broadcast to")
            return
        
        packet_data = packet.to_binary(self.compression_util)
        print(f"Broadcasting packet type {packet.message_type} to {len(self.connected_clients)} client(s)")
        
        for peer_id, client in self.connected_clients.items():
            try:
                print(f"Sending to peer {peer_id}")
                await self._send_raw_data(client, packet_data)
                print(f"Successfully sent to {peer_id}")
            except Exception as e:
                print(f"Error broadcasting to {peer_id}: {e}")
    
    async def _send_packet_to_peer(self, packet: BitchatPacket, peer_id: str):
        """Send packet to a specific peer"""
        print(f"📤 Attempting to send packet to peer {peer_id}")
        print(f"  Available connected clients: {list(self.connected_clients.keys())}")
        print(f"  Peer nicknames: {self.peer_nicknames}")
        
        if peer_id in self.connected_clients:
            client = self.connected_clients[peer_id]
            print(f"  ✅ Found direct connection to {peer_id}")
            await self._send_packet_to_client(packet, client)
        else:
            print(f"  ❌ No direct connection to {peer_id}, broadcasting instead")
            # Fallback: broadcast the packet (mesh networking)
            await self._broadcast_packet(packet)
    
    async def _send_packet_to_client(self, packet: BitchatPacket, client: BleakClient):
        """Send packet to a specific client"""
        packet_data = packet.to_binary(self.compression_util)
        await self._send_raw_data(client, packet_data)
    
    async def _send_raw_data(self, client: BleakClient, data: bytes):
        """Send raw data to a client"""
        try:
            print(f"\n=== SENDING PACKET ===")
            print(f"To: {client.address}")
            print(f"Size: {len(data)} bytes")
            print(f"Raw hex: {data.hex()}")
            print(f"Raw bytes: {list(data[:20])}{'...' if len(data) > 20 else ''}")
            
            # Find our characteristic using the services property
            target_service_uuid = BLE_SERVICE_UUID.lower()
            target_char_uuid = BLE_CHARACTERISTIC_UUID.lower()
            
            for service in client.services:
                service_uuid = str(service.uuid).lower()
                if service_uuid == target_service_uuid:
                    for char in service.characteristics:
                        char_uuid = str(char.uuid).lower()
                        if char_uuid == target_char_uuid:
                            # Check if characteristic supports writing
                            if "write" in char.properties or "write-without-response" in char.properties:
                                await client.write_gatt_char(char, data, response=False)
                                print(f"✅ Packet sent successfully")
                                print(f"=== END SEND ===\n")
                                return
                            else:
                                print(f"❌ BitChat characteristic found but doesn't support writing. Properties: {char.properties}")
                                return
            
            print(f"❌ BitChat characteristic not found for writing")
            print(f"Available services: {[str(s.uuid) for s in client.services]}")
            
        except Exception as e:
            print(f"❌ Error sending data: {e}")
            import traceback
            traceback.print_exc()
    
    async def _relay_packet(self, packet: BitchatPacket):
        """Relay packet to other peers with decreased TTL"""
        # Decrease TTL
        packet.ttl -= 1
        
        if packet.ttl > 0:
            await self._broadcast_packet(packet)
    
    async def _message_processor(self):
        """Process messages from the queue"""
        while self.running:
            try:
                await asyncio.sleep(0.1)  # Small processing delay
            except Exception as e:
                print(f"Error in message processor: {e}")
    
    async def _cleanup_loop(self):
        """Periodic cleanup of old data"""
        while self.running:
            try:
                current_time = time.time()
                
                # Clean up old processed messages
                if len(self.processed_messages) > self.max_processed_messages:
                    # Keep only recent half
                    recent_messages = list(self.processed_messages)[-self.max_processed_messages//2:]
                    self.processed_messages = set(recent_messages)
                
                # Clean up stale peers
                stale_peers = []
                for peer_id, peer_info in self.peers.items():
                    if current_time - peer_info.last_seen > 300:  # 5 minutes
                        stale_peers.append(peer_id)
                
                for peer_id in stale_peers:
                    del self.peers[peer_id]
                    if peer_id in self.connected_clients:
                        try:
                            await self.connected_clients[peer_id].disconnect()
                        except Exception:
                            pass
                        del self.connected_clients[peer_id]
                
                # Clean up old encryption sessions
                self.encryption_service.cleanup_old_sessions()
                
                await asyncio.sleep(60)  # Cleanup every minute
                
            except Exception as e:
                print(f"Error in cleanup loop: {e}")
                await asyncio.sleep(60)
    
    def _on_peer_authenticated(self, peer_id: str, fingerprint: str):
        """Callback when a peer is authenticated via Noise"""
        print(f"Peer {peer_id} authenticated with fingerprint: {fingerprint[:16]}...")
    
    def _on_handshake_required(self, peer_id: str):
        """Callback when handshake is required for a peer"""
        print(f"Handshake required for peer {peer_id}")
        # Start handshake
        asyncio.create_task(self._initiate_handshake(peer_id))
    
    async def _initiate_handshake(self, peer_id: str):
        """Initiate Noise handshake with a peer"""
        try:
            handshake_data = self.encryption_service.initiate_handshake(peer_id)
            
            packet = BitchatPacket(
                message_type=MessageType.NOISE_HANDSHAKE_INIT,
                sender_id=bytes.fromhex(self.my_peer_id),
                recipient_id=bytes.fromhex(peer_id),
                payload=handshake_data,
                ttl=1
            )
            
            await self._send_packet_to_peer(packet, peer_id)
            
        except Exception as e:
            print(f"Error initiating handshake with {peer_id}: {e}")
    
    def get_connected_peers(self) -> Dict[str, str]:
        """Get current connected peers for UI"""
        return self.peer_nicknames.copy()
    
    def get_peer_id_by_nickname(self, nickname: str) -> Optional[str]:
        """Find peer ID by nickname for DM functionality"""
        for peer_id, peer_nickname in self.peer_nicknames.items():
            if peer_nickname.lower() == nickname.lower():
                return peer_id
        return None
    
    def get_peer_count(self) -> int:
        """Get number of connected peers"""
        return len(self.connected_clients) 

    def find_peer_by_device_name(self, device_name: str) -> Optional[str]:
        """Find peer ID by device name"""
        for peer_id, client in self.connected_clients.items():
            if hasattr(client, '_device') and client._device.name == device_name:
                return peer_id
        return None 