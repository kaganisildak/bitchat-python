#!/usr/bin/env python3
"""
BitChat - Decentralized Mesh Chat via Bluetooth Low Energy
Python CLI client compatible with Swift/Rust implementations.

Usage:
    python bitchat.py [nickname]
    python bitchat.py --help
"""

import asyncio
import sys
import argparse
import signal
from typing import Optional

from encryption import EncryptionService
from ble_service import BitchatBLEService
from terminal_ux import BitchatTerminalUI
from persistence import BitchatPersistence, UserPreferences
from protocol import BitchatMessage

class BitChatApp:
    """
    Main BitChat application that coordinates all components.
    """
    
    def __init__(self, nickname: str, data_dir: Optional[str] = None):
        self.nickname = nickname
        
        # Initialize components
        self.persistence = BitchatPersistence(data_dir)
        self.encryption_service = EncryptionService(
            identity_path=self.persistence.get_identity_path()
        )
        self.ble_service = BitchatBLEService(nickname, self.encryption_service)
        self.ui = BitchatTerminalUI(nickname)
        
        # Application state
        self.running = False
        self.shutdown_event = asyncio.Event()
        
        # Load preferences
        self.preferences = self.persistence.load_preferences()
        
        # Initialize persistence with current nickname
        self.state = self.persistence.initialize(nickname)
        
        # Setup callbacks
        self._setup_callbacks()
        
        # Setup signal handlers
        self._setup_signal_handlers()
    
    def _setup_callbacks(self):
        """Setup callbacks between components"""
        
        # BLE service callbacks
        self.ble_service.on_message_received = self._on_message_received
        self.ble_service.on_peer_connected = self._on_peer_connected
        self.ble_service.on_peer_discovered = self._on_peer_discovered  # Make sure this is set
        
        # UI callbacks
        self.ui.on_message_send = self._on_message_send
        
        # Add debug callbacks for terminal UI
        self.ui.ble_service_debug_callback = self._debug_ble_service
        self.ui.connection_status_callback = self._show_connection_status
    
    def _debug_ble_service(self):
        """Provide BLE service debug info to terminal UI"""
        print("\n[BLE SERVICE DEBUG]")
        print(f"  My peer ID: {self.ble_service.my_peer_id}")
        print(f"  My nickname: {self.ble_service.nickname}")
        print(f"  Connected clients: {list(self.ble_service.connected_clients.keys())}")
        print(f"  Peer nicknames: {self.ble_service.peer_nicknames}")
        print(f"  Tracked peers: {list(self.ble_service.peers.keys())}")
        print(f"  Service running: {self.ble_service.running}")
    
    def _show_connection_status(self):
        """Show current BLE connection status"""
        print("\n[CONNECTION STATUS]")
        print(f"  BLE service running: {self.ble_service.running}")
        print(f"  Connected clients: {len(self.ble_service.connected_clients)}")
        
        for peer_id, client in self.ble_service.connected_clients.items():
            nickname = self.ble_service.peer_nicknames.get(peer_id, "Unknown")
            connected = client.is_connected if hasattr(client, 'is_connected') else "Unknown"
            print(f"    • {nickname} ({peer_id[:8]}...) - Connected: {connected}")
        
        if not self.ble_service.connected_clients:
            print("    No active BLE connections")
        
        # Encryption service callbacks
        self.encryption_service.on_peer_authenticated = self._on_peer_authenticated
        self.encryption_service.on_handshake_required = self._on_handshake_required
        
        # Set identity fingerprint in UI
        fingerprint = self.encryption_service.get_identity_fingerprint()
        self.ui.set_identity_fingerprint(fingerprint)
        
        # Set peer ID in UI
        self.ui.set_peer_id(self.ble_service.my_peer_id)
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(sig, frame):
            print("\nReceived signal, shutting down...")
            self.shutdown_event.set()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    async def start(self):
        """Start the BitChat application"""
        if self.running:
            return
        
        print(f"Starting BitChat with nickname: {self.nickname}")
        print(f"Identity fingerprint: {self.encryption_service.get_identity_fingerprint()}")
        
        self.running = True
        
        try:
            # Start all services
            await self.ui.start()
            await self.ble_service.start()
            
            # Load message history into UI
            await self._load_message_history()
            
            # Start background tasks
            auto_save_task = asyncio.create_task(self._auto_save_loop())
            
            # Wait for shutdown
            await self.shutdown_event.wait()
            
        except Exception as e:
            print(f"Error during startup: {e}")
            raise
        finally:
            # Cleanup
            await self._shutdown()
    
    async def _shutdown(self):
        """Shutdown the application gracefully"""
        if not self.running:
            return
        
        print("Shutting down BitChat...")
        self.running = False
        
        # Stop services
        await self.ble_service.stop()
        await self.ui.stop()
        
        # Force save state
        self.persistence.force_save()
        
        print("BitChat stopped.")
    
    async def _load_message_history(self):
        """Load recent message history into UI"""
        # Load recent messages (last 50)
        recent_messages = self.persistence.get_message_history(limit=50)
        
        for message in recent_messages:
            await self.ui.add_message(message)
        
        # Update peers
        known_peers = self.persistence.get_known_peers()
        peer_nicknames = {
            peer_id: info['nickname'] 
            for peer_id, info in known_peers.items()
        }
        await self.ui.update_peers(peer_nicknames)
    
    async def _auto_save_loop(self):
        """Periodically auto-save state"""
        while self.running:
            try:
                await asyncio.sleep(60)  # Check every minute
                self.persistence.auto_save_if_needed()
            except Exception as e:
                print(f"Error in auto-save: {e}")
    
    # Event handlers
    async def _on_message_received(self, message: BitchatMessage):
        """Handle received message"""
        # Check if sender is blocked
        if message.sender_peer_id and self.persistence.is_blocked(message.sender_peer_id):
            return  # Silently ignore blocked users
        
        # Add to persistence
        self.persistence.add_message(message)
        
        # Add sender to known peers
        if message.sender_peer_id:
            self.persistence.add_known_peer(
                message.sender_peer_id, 
                message.sender,
                self.encryption_service.get_peer_fingerprint(message.sender_peer_id)
            )
        
        # Show in UI
        await self.ui.add_message(message)
        
        # Update channel membership if this is a channel message
        if message.channel:
            self.persistence.join_channel(message.channel)
    
    async def _on_message_send(self, content: str, channel: Optional[str], recipient_peer_id: Optional[str]):
        """Handle sending a message"""
        try:
            # Send via BLE service
            await self.ble_service.send_message(
                content=content,
                channel=channel,
                recipient_peer_id=recipient_peer_id
            )
            
            # Create local message for display
            message = BitchatMessage(
                id="",  # Will be auto-generated
                sender=self.nickname,
                content=content,
                timestamp=time.time(),
                is_private=recipient_peer_id is not None,
                sender_peer_id=self.ble_service.my_peer_id,
                channel=channel
            )
            
            # Add to persistence and UI
            self.persistence.add_message(message)
            await self.ui.add_message(message)
            
            # Update channel membership
            if channel:
                self.persistence.join_channel(channel)
                
        except Exception as e:
            print(f"Error sending message: {e}")
    
    async def _on_peer_discovered(self, peer_id: str, nickname: str):
        """Handle peer discovery"""
        print(f"DEBUG: Peer discovered - {peer_id} ({nickname})")
        
        # Store peer info
        self.persistence.add_known_peer(peer_id, nickname)
        
        # Update UI
        connected_peers = self.ble_service.get_connected_peers()
        print(f"DEBUG: Updating UI with peers: {connected_peers}")
        await self.ui.update_peers(connected_peers)
    
    async def _on_peer_connected(self, peer_id: str):
        """Handle peer connection"""
        print(f"DEBUG: Peer connected - {peer_id}")
        
        # Get peer info
        peers = self.ble_service.get_connected_peers()
        nickname = peers.get(peer_id, "Unknown")
        
        # Show in UI
        await self.ui.show_peer_connected(peer_id, nickname)
        
        # Update peers list
        await self.ui.update_peers(peers)
    
    async def _on_peer_disconnected(self, peer_id: str):
        """Handle peer disconnection"""
        # Show in UI
        await self.ui.show_peer_disconnected(peer_id)
        
        # Update peers list
        connected_peers = self.ble_service.get_connected_peers()
        await self.ui.update_peers(connected_peers)
    
    async def _on_peer_authenticated(self, peer_id: str, fingerprint: str):
        """Handle peer authentication via Noise"""
        # Update known peers with fingerprint
        peers = self.ble_service.get_connected_peers()
        nickname = peers.get(peer_id, "Unknown")
        self.persistence.add_known_peer(peer_id, nickname, fingerprint)
        
        # Show encryption status in UI
        await self.ui.show_encryption_status(peer_id, fingerprint)
        
        # Update fingerprints
        all_fingerprints = {}
        for active_peer in self.encryption_service.get_active_peers():
            fp = self.encryption_service.get_peer_fingerprint(active_peer)
            if fp:
                all_fingerprints[active_peer] = fp
        
        await self.ui.update_peer_fingerprints(all_fingerprints)
    
    async def _on_handshake_required(self, peer_id: str):
        """Handle handshake requirement"""
        print(f"Handshake required for peer {peer_id}")
        # The BLE service will handle the handshake initiation

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="BitChat - Decentralized Mesh Chat via Bluetooth Low Energy"
    )
    
    parser.add_argument(
        "nickname",
        nargs="?",
        default=None,
        help="Your nickname for the chat (will prompt if not provided)"
    )
    
    parser.add_argument(
        "--data-dir",
        help="Custom data directory for storing state and preferences"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="BitChat Python CLI 1.0.0"
    )
    
    args = parser.parse_args()
    
    # Get nickname
    nickname = args.nickname
    if not nickname:
        try:
            nickname = input("Enter your nickname: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting...")
            return 1
    
    if not nickname:
        print("Error: Nickname is required")
        return 1
    
    # Validate nickname
    if len(nickname) > 32:
        print("Error: Nickname must be 32 characters or less")
        return 1
    
    if not nickname.replace(" ", "").replace("-", "").replace("_", "").isalnum():
        print("Error: Nickname must contain only letters, numbers, spaces, hyphens, and underscores")
        return 1
    
    # Check platform requirements
    if sys.platform not in ['linux', 'darwin', 'win32']:
        print(f"Warning: Platform {sys.platform} may not be fully supported")
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("Error: Python 3.8 or higher is required")
        return 1
    
    # Create and run application
    try:
        app = BitChatApp(nickname, args.data_dir)
        asyncio.run(app.start())
        return 0
        
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
        return 0
    except Exception as e:
        print(f"Error: {e}")
        return 1

if __name__ == "__main__":
    import time  # Need to import time for timestamp usage
    sys.exit(main()) 