"""
Terminal User Experience for BitChat
Provides a rich, asynchronous command-line interface.
"""

import asyncio
import time
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from datetime import datetime

import aioconsole
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.layout import Layout
from rich.live import Live
from rich.align import Align
from rich.markdown import Markdown

from protocol import BitchatMessage

@dataclass
class ChatContext:
    """Current chat context and state"""
    current_channel: Optional[str] = None
    current_recipient: Optional[str] = None
    show_system_messages: bool = True
    show_timestamps: bool = True
    max_message_history: int = 100

class BitchatTerminalUI:
    """
    Rich terminal interface for BitChat.
    Provides real-time message display and async command input.
    """
    
    def __init__(self, nickname: str):
        self.nickname = nickname
        self.console = Console()
        self.context = ChatContext()
        
        # Message history
        self.messages: List[BitchatMessage] = []
        self.system_messages: List[str] = []
        
        # Peer tracking
        self.connected_peers: Dict[str, str] = {}  # peer_id -> nickname
        self.peer_fingerprints: Dict[str, str] = {}  # peer_id -> fingerprint
        
        # UI state
        self.running = False
        self.input_task = None
        self.display_task = None
        self.layout = None
        self.live = None
        
        # Callbacks
        self.on_message_send: Optional[Callable[[str, Optional[str], Optional[str]], None]] = None
        self.on_command: Optional[Callable[[str, List[str]], None]] = None
        
        # Commands
        self.commands = {
            'help': self._cmd_help,
            'status': self._cmd_status,
            'fingerprint': self._cmd_fingerprint,
            'dm': self._cmd_dm,
            'peers': self._cmd_peers,
            'debug': self._cmd_debug,
            'connections': self._cmd_connections,
            'quit': self._cmd_quit,
            'exit': self._cmd_quit
        }
    
    async def start(self):
        """Start the terminal UI"""
        if self.running:
            return
        
        self.running = True
        
        # Show welcome matching terminal design
        await self._show_welcome()
        
        # Start UI tasks
        self.input_task = asyncio.create_task(self._input_loop())
        
        # Show initial help
        self.console.print(">> Using saved nickname:", style="dim yellow", end=" ")
        self.console.print(self.nickname, style="bold yellow")
        self.console.print(">> Type /status to see connection info", style="dim yellow")
    
    async def stop(self):
        """Stop the terminal UI"""
        if not self.running:
            return
        
        self.running = False
        
        # Cancel tasks
        if self.input_task:
            self.input_task.cancel()
        
        # Clear and show goodbye
        self.console.print("\n[bold cyan]BitChat session ended[/bold cyan]")
    
    # Layout methods removed - using simple console output instead
    
    # Removed display loop - using simple terminal output
    
    # Removed layout generation methods
    
    # All layout generation methods removed - using simple terminal output
    
    async def _input_loop(self):
        """Handle user input"""
        while self.running:
            try:
                # Read input asynchronously
                user_input = await aioconsole.ainput("")
                
                if not user_input.strip():
                    continue
                
                # Handle commands
                if user_input.startswith('/'):
                    await self._handle_command(user_input[1:])
                else:
                    # Send message
                    await self._handle_message_send(user_input)
                
            except (EOFError, KeyboardInterrupt):
                await self._cmd_quit([])
                break
            except Exception as e:
                await self._add_system_message(f"Input error: {e}")
    
    async def _handle_command(self, command_line: str):
        """Handle a command"""
        parts = command_line.split()
        if not parts:
            return
        
        command = parts[0].lower()
        args = parts[1:]
        
        if command in self.commands:
            await self.commands[command](args)
        else:
            await self._add_system_message(f"Unknown command: {command}. Type /help for available commands.")
    
    async def _handle_message_send(self, content: str):
        """Handle sending a message"""
        if self.on_message_send:
            asyncio.create_task(self.on_message_send(
                content,
                self.context.current_channel,
                self.context.current_recipient
            ))
    
    # Command handlers
    async def _cmd_help(self, args: List[str]):
        """Show help"""
        help_text = """
Available Commands:
  /help           - Show this help
  /status         - Show connection status
  /peers          - List connected peers
  /dm <nick> <msg> - Send direct message to peer
  /debug          - Show detailed peer tracking debug info
  /connections    - Show BLE connection status
  /fingerprint    - Show your identity fingerprint
  /quit, /exit    - Exit BitChat

Examples:
  /dm anon3276 Hello there!
  /peers
  /debug
  /connections
  /status

Just type a message (without /) to send to all peers.
        """
        self.console.print(help_text.strip(), style="dim cyan")
    
    async def _cmd_dm(self, args: List[str]):
        """Send a direct message to a specific peer"""
        if len(args) < 2:
            self.console.print("[red]Usage: /dm <nickname> <message>[/red]")
            self.console.print("[dim]Use /peers to see available peers[/dim]")
            return
        
        target_nickname = args[0]
        message_content = " ".join(args[1:])
        
        # Debug: Show current peers
        self.console.print(f"[dim]Looking for '{target_nickname}' in peers: {list(self.connected_peers.values())}[/dim]")
        
        # Find peer ID by nickname (case-insensitive)
        target_peer_id = None
        for peer_id, nickname in self.connected_peers.items():
            if nickname.lower() == target_nickname.lower():
                target_peer_id = peer_id
                break
        
        if not target_peer_id:
            self.console.print(f"[red]Peer '{target_nickname}' not found.[/red]")
            if self.connected_peers:
                self.console.print(f"[dim]Available peers: {', '.join(self.connected_peers.values())}[/dim]")
                self.console.print("[dim]Use /debug for more details[/dim]")
            else:
                self.console.print("[dim]No peers connected. Wait for peer discovery or use /debug[/dim]")
            return
        
        self.console.print(f"[dim]Found peer: {target_nickname} -> {target_peer_id[:8]}...[/dim]")
        
        # Send DM
        if self.on_message_send:
            asyncio.create_task(self.on_message_send(
                message_content,
                None,  # No channel for DMs
                target_peer_id  # Recipient peer ID
            ))
            
            # Show our sent DM in console
            timestamp = datetime.now().strftime('%H:%M')
            self.console.print(f"[{timestamp}] ", style="dim", end="")
            self.console.print(f"<{self.nickname}>", style="bold green", end=" ")
            self.console.print(f"→ {target_nickname}: ", style="magenta", end="")
            self.console.print(message_content)
        else:
            self.console.print("[red]Message sending not available[/red]")

    async def _cmd_peers(self, args: List[str]):
        """List connected peers"""
        if not self.connected_peers:
            self.console.print("[yellow]No peers connected[/yellow]")
            return
        
        self.console.print()
        self.console.print("Connected Peers:", style="bold")
        for peer_id, nickname in self.connected_peers.items():
            # Show encryption status
            encrypted = "🔒" if peer_id in self.peer_fingerprints else "🔓"
            self.console.print(f"  • {nickname} ({peer_id[:8]}...) {encrypted}")
        self.console.print()
    
    async def _cmd_channel(self, args: List[str]):
        """Join a channel"""
        if not args:
            await self._add_system_message("Usage: /channel <name> (e.g., /channel #general)")
            return
        
        channel = args[0]
        if not channel.startswith('#'):
            channel = '#' + channel
        
        self.context.current_channel = channel
        self.context.current_recipient = None
        await self._add_system_message(f"Joined channel {channel}")
    
    async def _cmd_clear(self, args: List[str]):
        """Clear chat history"""
        self.messages.clear()
        self.system_messages.clear()
        await self._add_system_message("Chat history cleared")
    
    async def _cmd_status(self, args: List[str]):
        """Show connection status"""
        peer_count = len(self.connected_peers)
        encrypted_count = len(self.peer_fingerprints)
        
        # Show status in terminal style matching the image
        self.console.print()
        self.console.print("─── Connection Status ───", style="bold")
        self.console.print(f"Peers connected:     {peer_count}")
        self.console.print(f"Active channels:     0")  # TODO: implement channels
        self.console.print(f"Active DMs:          0")  # TODO: implement DMs
        self.console.print()
        self.console.print(f"Your nickname: {self.nickname}")
        
        # Show our peer ID like in the image (truncated for display)
        peer_id = getattr(self, 'my_peer_id', 'unknown')
        if len(peer_id) > 8:
            displayed_id = peer_id[:8] + "..."
        else:
            displayed_id = peer_id
        self.console.print(f"Your ID: {displayed_id}")
        self.console.print()
    
    async def _cmd_fingerprint(self, args: List[str]):
        """Show identity fingerprint"""
        # This will need to be connected to the encryption service
        await self._add_system_message("Identity fingerprint: [Available after connecting to encryption service]")
    
    async def _cmd_debug(self, args: List[str]):
        """Debug peer tracking and connections"""
        self.console.print("\n[bold]=== COMPREHENSIVE DEBUG INFO ===[/bold]")
        
        # UI peer tracking
        self.console.print("\n[yellow]UI Peer Tracking:[/yellow]")
        self.console.print(f"  Connected peers dict: {self.connected_peers}")
        self.console.print(f"  Peer fingerprints: {self.peer_fingerprints}")
        
        # Show peer details
        if self.connected_peers:
            self.console.print("\n[yellow]Tracked Peers:[/yellow]")
            for peer_id, nickname in self.connected_peers.items():
                encrypted = "🔒" if peer_id in self.peer_fingerprints else "🔓"
                self.console.print(f"  • {nickname} ({peer_id[:8]}...{peer_id[-8:]}) {encrypted}")
        else:
            self.console.print("[red]  No peers tracked in UI[/red]")
        
        # Try to get info from BLE service if available
        if hasattr(self, 'ble_service_debug_callback'):
            self.console.print("\n[yellow]Requesting BLE service debug info...[/yellow]")
            self.ble_service_debug_callback()
        
        self.console.print()

    async def _cmd_connections(self, args: List[str]):
        """Show current BLE connection status"""
        self.console.print("\n[bold]=== CONNECTION STATUS ===[/bold]")
        self.console.print("[dim]This shows the actual BLE connection state[/dim]")
        
        if hasattr(self, 'connection_status_callback'):
            self.connection_status_callback()
        else:
            self.console.print("[yellow]Connection status callback not available[/yellow]")
        
        self.console.print()

    async def _cmd_quit(self, args: List[str]):
        """Quit the application"""
        await self._add_system_message("Shutting down...")
        self.running = False
    
    def _get_context_description(self) -> str:
        """Get description of current context"""
        if self.context.current_channel:
            return f"Channel {self.context.current_channel}"
        elif self.context.current_recipient:
            nickname = self.connected_peers.get(self.context.current_recipient, "Unknown")
            return f"DM with {nickname}"
        else:
            return "Public chat"
    
    # Public methods for external interaction
    async def add_message(self, message: BitchatMessage):
        """Add a received message to the display"""
        self.messages.append(message)
        
        # Display message immediately in terminal style
        timestamp = datetime.fromtimestamp(message.timestamp).strftime('%H:%M')
        
        if message.is_private:
            # This is a DM - show with special formatting
            if message.sender == self.nickname:
                # Our outgoing DM (shouldn't happen here, but just in case)
                self.console.print(f"[{timestamp}] ", style="dim", end="")
                self.console.print(f"<{message.sender}>", style="bold green", end=" ")
                self.console.print(f"→ {message.recipient_nickname or 'Unknown'}: ", style="magenta", end="")
                self.console.print(message.content)
            else:
                # Incoming DM
                self.console.print(f"[{timestamp}] ", style="dim", end="")
                self.console.print(f"<{message.sender}>", style="bold magenta", end=" ")
                self.console.print("→ you: ", style="magenta", end="")
                self.console.print(message.content)
        elif message.sender == self.nickname:
            # Our public message - show with different style
            self.console.print(f"[{timestamp}] ", style="dim", end="")
            self.console.print(f"<{message.sender}>", style="bold green", end=" ")
            self.console.print(message.content)
        else:
            # Other's public message
            self.console.print(f"[{timestamp}] ", style="dim", end="")
            self.console.print(f"<{message.sender}>", style="bold cyan", end=" ")
            self.console.print(message.content)
        
        # Trim message history
        if len(self.messages) > self.context.max_message_history:
            self.messages = self.messages[-self.context.max_message_history:]
    
    async def _add_system_message(self, text: str):
        """Add a system message"""
        self.system_messages.append(text)
        
        # Trim system message history
        if len(self.system_messages) > 20:
            self.system_messages = self.system_messages[-20:]
    
    async def update_peers(self, peers: Dict[str, str]):
        """Update the connected peers list"""
        self.connected_peers = peers.copy()
    
    async def update_peer_fingerprints(self, fingerprints: Dict[str, str]):
        """Update peer fingerprints for encryption status"""
        self.peer_fingerprints = fingerprints.copy()
    
    async def show_peer_connected(self, peer_id: str, nickname: str):
        """Show that a peer connected"""
        self.connected_peers[peer_id] = nickname
        
        # Show connection in terminal style matching the image
        self.console.print(f">> Found bitchat service! Connecting...", style="yellow")
        self.console.print(f"{nickname} connected", style="bold yellow")
    
    async def show_peer_disconnected(self, peer_id: str):
        """Show that a peer disconnected"""
        nickname = self.connected_peers.get(peer_id, "Unknown")
        if peer_id in self.connected_peers:
            del self.connected_peers[peer_id]
        if peer_id in self.peer_fingerprints:
            del self.peer_fingerprints[peer_id]
        await self._add_system_message(f"{nickname} disconnected")
    
    async def show_encryption_status(self, peer_id: str, fingerprint: str):
        """Show encryption established with peer"""
        self.peer_fingerprints[peer_id] = fingerprint
        nickname = self.connected_peers.get(peer_id, "Unknown")
        await self._add_system_message(f"Secure connection established with {nickname}")
    
    async def _show_welcome(self):
        """Show welcome message matching the terminal design"""
        # Clear screen first
        self.console.clear()
        
        # Green header bar matching the design
        header = Text()
        header.append("Decentralized • Encrypted • Peer-to-Peer • Open Source\n", style="bold white on green")
        header.append("bitchat@ the terminal v1.0.0", style="bold white on green")
        
        self.console.print(header)
        self.console.print()  # Empty line
        
        # Status messages
        self.console.print(">> Scanning for bitchat service...", style="yellow")
        
        await asyncio.sleep(1)  # Brief pause for effect
    
    def set_identity_fingerprint(self, fingerprint: str):
        """Set our identity fingerprint for display"""
        self.identity_fingerprint = fingerprint
        
        # Update fingerprint command
        async def _cmd_fingerprint_updated(args: List[str]):
            await self._add_system_message(f"Your identity fingerprint: {fingerprint}")
        
        self.commands['fingerprint'] = _cmd_fingerprint_updated
    
    def set_peer_id(self, peer_id: str):
        """Set our peer ID for display"""
        self.my_peer_id = peer_id 