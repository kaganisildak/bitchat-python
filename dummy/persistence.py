"""
Persistence layer for BitChat
Handles saving and loading application state, preferences, and data.
"""

import json
import os
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any
from pathlib import Path

from protocol import BitchatMessage

@dataclass
class BitchatState:
    """Complete application state"""
    nickname: str
    last_updated: float
    preferences: Dict[str, Any]
    message_history: List[Dict[str, Any]]
    known_peers: Dict[str, Dict[str, Any]]
    channel_memberships: List[str]
    blocked_peers: List[str]
    favorite_peers: List[str]

@dataclass
class UserPreferences:
    """User preferences and settings"""
    show_timestamps: bool = True
    show_system_messages: bool = True
    max_message_history: int = 1000
    auto_save_interval: int = 300  # seconds
    enable_encryption: bool = True
    default_ttl: int = 3
    theme: str = "default"
    notification_sound: bool = False

class BitchatPersistence:
    """
    Manages persistence of BitChat application state.
    Handles saving/loading of messages, peers, preferences, etc.
    """
    
    def __init__(self, data_dir: Optional[str] = None):
        # Set up data directory
        if data_dir:
            self.data_dir = Path(data_dir)
        else:
            # Use platform-appropriate data directory
            home = Path.home()
            if os.name == 'nt':  # Windows
                self.data_dir = home / "AppData" / "Local" / "BitChat2"
            elif os.name == 'posix':  # Unix/Linux/macOS
                self.data_dir = home / ".local" / "share" / "bitchat2"
            else:
                self.data_dir = home / ".bitchat2"
        
        # Ensure data directory exists
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # File paths
        self.state_file = self.data_dir / "state.json"
        self.preferences_file = self.data_dir / "preferences.json"
        self.identity_file = self.data_dir / "identity.key"
        self.message_cache_file = self.data_dir / "messages.json"
        self.peers_file = self.data_dir / "peers.json"
        
        # Current state
        self.current_state: Optional[BitchatState] = None
        self.preferences: UserPreferences = UserPreferences()
        
        # Auto-save tracking
        self.last_save_time = 0
        self.save_pending = False
    
    def initialize(self, nickname: str) -> BitchatState:
        """Initialize or load existing state"""
        # Try to load existing state
        if self.state_file.exists():
            try:
                state = self.load_state()
                if state:
                    # Update nickname if different
                    if state.nickname != nickname:
                        state.nickname = nickname
                        self.save_state(state)
                    self.current_state = state
                    return state
            except Exception as e:
                print(f"Warning: Could not load existing state: {e}")
        
        # Create new state
        state = BitchatState(
            nickname=nickname,
            last_updated=time.time(),
            preferences=asdict(self.preferences),
            message_history=[],
            known_peers={},
            channel_memberships=[],
            blocked_peers=[],
            favorite_peers=[]
        )
        
        self.current_state = state
        self.save_state(state)
        return state
    
    def load_state(self) -> Optional[BitchatState]:
        """Load application state from file"""
        try:
            if not self.state_file.exists():
                return None
            
            with open(self.state_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Convert to BitchatState
            state = BitchatState(
                nickname=data.get('nickname', ''),
                last_updated=data.get('last_updated', time.time()),
                preferences=data.get('preferences', {}),
                message_history=data.get('message_history', []),
                known_peers=data.get('known_peers', {}),
                channel_memberships=data.get('channel_memberships', []),
                blocked_peers=data.get('blocked_peers', []),
                favorite_peers=data.get('favorite_peers', [])
            )
            
            return state
            
        except Exception as e:
            print(f"Error loading state: {e}")
            return None
    
    def save_state(self, state: BitchatState):
        """Save application state to file"""
        try:
            state.last_updated = time.time()
            
            # Convert to dictionary
            data = asdict(state)
            
            # Write to file with backup
            temp_file = self.state_file.with_suffix('.tmp')
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            # Atomic replace
            temp_file.replace(self.state_file)
            
            self.last_save_time = time.time()
            self.save_pending = False
            
        except Exception as e:
            print(f"Error saving state: {e}")
    
    def load_preferences(self) -> UserPreferences:
        """Load user preferences"""
        try:
            if not self.preferences_file.exists():
                return UserPreferences()
            
            with open(self.preferences_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Create preferences object with defaults for missing fields
            prefs = UserPreferences()
            for key, value in data.items():
                if hasattr(prefs, key):
                    setattr(prefs, key, value)
            
            return prefs
            
        except Exception as e:
            print(f"Error loading preferences: {e}")
            return UserPreferences()
    
    def save_preferences(self, preferences: UserPreferences):
        """Save user preferences"""
        try:
            data = asdict(preferences)
            
            with open(self.preferences_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            
            self.preferences = preferences
            
        except Exception as e:
            print(f"Error saving preferences: {e}")
    
    def add_message(self, message: BitchatMessage):
        """Add a message to persistent storage"""
        if not self.current_state:
            return
        
        # Convert message to dictionary
        message_dict = {
            'id': message.id,
            'sender': message.sender,
            'content': message.content,
            'timestamp': message.timestamp,
            'is_relay': message.is_relay,
            'original_sender': message.original_sender,
            'is_private': message.is_private,
            'recipient_nickname': message.recipient_nickname,
            'sender_peer_id': message.sender_peer_id,
            'mentions': message.mentions,
            'channel': message.channel,
            'is_encrypted': message.is_encrypted
        }
        
        # Add to history
        self.current_state.message_history.append(message_dict)
        
        # Trim history if too long
        max_history = self.preferences.max_message_history
        if len(self.current_state.message_history) > max_history:
            self.current_state.message_history = self.current_state.message_history[-max_history:]
        
        self.mark_for_save()
    
    def get_message_history(self, channel: Optional[str] = None, 
                           peer_id: Optional[str] = None, 
                           limit: Optional[int] = None) -> List[BitchatMessage]:
        """Get message history with optional filtering"""
        if not self.current_state:
            return []
        
        messages = []
        for msg_dict in self.current_state.message_history:
            # Apply filters
            if channel and msg_dict.get('channel') != channel:
                continue
            if peer_id and msg_dict.get('sender_peer_id') != peer_id:
                continue
            
            # Convert back to BitchatMessage
            try:
                message = BitchatMessage(
                    id=msg_dict.get('id', ''),
                    sender=msg_dict.get('sender', ''),
                    content=msg_dict.get('content', ''),
                    timestamp=msg_dict.get('timestamp', time.time()),
                    is_relay=msg_dict.get('is_relay', False),
                    original_sender=msg_dict.get('original_sender'),
                    is_private=msg_dict.get('is_private', False),
                    recipient_nickname=msg_dict.get('recipient_nickname'),
                    sender_peer_id=msg_dict.get('sender_peer_id'),
                    mentions=msg_dict.get('mentions'),
                    channel=msg_dict.get('channel'),
                    is_encrypted=msg_dict.get('is_encrypted', False)
                )
                messages.append(message)
            except Exception as e:
                print(f"Error reconstructing message: {e}")
                continue
        
        # Apply limit
        if limit:
            messages = messages[-limit:]
        
        return messages
    
    def add_known_peer(self, peer_id: str, nickname: str, fingerprint: Optional[str] = None):
        """Add or update a known peer"""
        if not self.current_state:
            return
        
        peer_info = {
            'nickname': nickname,
            'first_seen': time.time(),
            'last_seen': time.time(),
            'fingerprint': fingerprint
        }
        
        # Update existing or add new
        if peer_id in self.current_state.known_peers:
            existing = self.current_state.known_peers[peer_id]
            peer_info['first_seen'] = existing.get('first_seen', time.time())
            peer_info['last_seen'] = time.time()
            if not fingerprint and 'fingerprint' in existing:
                peer_info['fingerprint'] = existing['fingerprint']
        
        self.current_state.known_peers[peer_id] = peer_info
        self.mark_for_save()
    
    def get_known_peers(self) -> Dict[str, Dict[str, Any]]:
        """Get all known peers"""
        if not self.current_state:
            return {}
        return self.current_state.known_peers.copy()
    
    def add_to_favorites(self, peer_id: str):
        """Add a peer to favorites"""
        if not self.current_state:
            return
        
        if peer_id not in self.current_state.favorite_peers:
            self.current_state.favorite_peers.append(peer_id)
            self.mark_for_save()
    
    def remove_from_favorites(self, peer_id: str):
        """Remove a peer from favorites"""
        if not self.current_state:
            return
        
        if peer_id in self.current_state.favorite_peers:
            self.current_state.favorite_peers.remove(peer_id)
            self.mark_for_save()
    
    def is_favorite(self, peer_id: str) -> bool:
        """Check if a peer is in favorites"""
        if not self.current_state:
            return False
        return peer_id in self.current_state.favorite_peers
    
    def block_peer(self, peer_id: str):
        """Block a peer"""
        if not self.current_state:
            return
        
        if peer_id not in self.current_state.blocked_peers:
            self.current_state.blocked_peers.append(peer_id)
            # Remove from favorites if present
            if peer_id in self.current_state.favorite_peers:
                self.current_state.favorite_peers.remove(peer_id)
            self.mark_for_save()
    
    def unblock_peer(self, peer_id: str):
        """Unblock a peer"""
        if not self.current_state:
            return
        
        if peer_id in self.current_state.blocked_peers:
            self.current_state.blocked_peers.remove(peer_id)
            self.mark_for_save()
    
    def is_blocked(self, peer_id: str) -> bool:
        """Check if a peer is blocked"""
        if not self.current_state:
            return False
        return peer_id in self.current_state.blocked_peers
    
    def join_channel(self, channel: str):
        """Remember channel membership"""
        if not self.current_state:
            return
        
        if channel not in self.current_state.channel_memberships:
            self.current_state.channel_memberships.append(channel)
            self.mark_for_save()
    
    def leave_channel(self, channel: str):
        """Remove channel membership"""
        if not self.current_state:
            return
        
        if channel in self.current_state.channel_memberships:
            self.current_state.channel_memberships.remove(channel)
            self.mark_for_save()
    
    def get_channels(self) -> List[str]:
        """Get list of joined channels"""
        if not self.current_state:
            return []
        return self.current_state.channel_memberships.copy()
    
    def mark_for_save(self):
        """Mark state as needing to be saved"""
        self.save_pending = True
    
    def auto_save_if_needed(self):
        """Save state if auto-save interval has passed"""
        if not self.save_pending or not self.current_state:
            return
        
        current_time = time.time()
        if current_time - self.last_save_time >= self.preferences.auto_save_interval:
            self.save_state(self.current_state)
    
    def force_save(self):
        """Force immediate save of current state"""
        if self.current_state:
            self.save_state(self.current_state)
    
    def clear_message_history(self):
        """Clear all message history"""
        if not self.current_state:
            return
        
        self.current_state.message_history.clear()
        self.mark_for_save()
    
    def export_data(self, export_path: str) -> bool:
        """Export all data to a file"""
        try:
            export_data = {
                'version': '1.0',
                'exported_at': time.time(),
                'state': asdict(self.current_state) if self.current_state else None,
                'preferences': asdict(self.preferences)
            }
            
            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            return True
            
        except Exception as e:
            print(f"Error exporting data: {e}")
            return False
    
    def import_data(self, import_path: str) -> bool:
        """Import data from a file"""
        try:
            with open(import_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Import state if present
            if 'state' in data and data['state']:
                state_data = data['state']
                self.current_state = BitchatState(
                    nickname=state_data.get('nickname', ''),
                    last_updated=time.time(),
                    preferences=state_data.get('preferences', {}),
                    message_history=state_data.get('message_history', []),
                    known_peers=state_data.get('known_peers', {}),
                    channel_memberships=state_data.get('channel_memberships', []),
                    blocked_peers=state_data.get('blocked_peers', []),
                    favorite_peers=state_data.get('favorite_peers', [])
                )
                self.force_save()
            
            # Import preferences if present
            if 'preferences' in data:
                prefs_data = data['preferences']
                prefs = UserPreferences()
                for key, value in prefs_data.items():
                    if hasattr(prefs, key):
                        setattr(prefs, key, value)
                self.save_preferences(prefs)
            
            return True
            
        except Exception as e:
            print(f"Error importing data: {e}")
            return False
    
    def get_identity_path(self) -> str:
        """Get path for identity key storage"""
        return str(self.identity_file)
    
    def cleanup_old_data(self, days: int = 30):
        """Clean up old data"""
        if not self.current_state:
            return
        
        cutoff_time = time.time() - (days * 24 * 60 * 60)
        
        # Clean old messages
        original_count = len(self.current_state.message_history)
        self.current_state.message_history = [
            msg for msg in self.current_state.message_history
            if msg.get('timestamp', 0) > cutoff_time
        ]
        
        cleaned_count = original_count - len(self.current_state.message_history)
        if cleaned_count > 0:
            print(f"Cleaned up {cleaned_count} old messages")
            self.mark_for_save()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get usage statistics"""
        if not self.current_state:
            return {}
        
        stats = {
            'total_messages': len(self.current_state.message_history),
            'known_peers': len(self.current_state.known_peers),
            'favorite_peers': len(self.current_state.favorite_peers),
            'blocked_peers': len(self.current_state.blocked_peers),
            'channels': len(self.current_state.channel_memberships),
            'data_size_mb': self._calculate_data_size() / (1024 * 1024)
        }
        
        # Message statistics
        if self.current_state.message_history:
            timestamps = [msg.get('timestamp', 0) for msg in self.current_state.message_history]
            stats['oldest_message'] = min(timestamps)
            stats['newest_message'] = max(timestamps)
        
        return stats
    
    def _calculate_data_size(self) -> int:
        """Calculate total data size in bytes"""
        total_size = 0
        
        # Check all data files
        for file_path in [self.state_file, self.preferences_file, self.message_cache_file, self.peers_file]:
            if file_path.exists():
                total_size += file_path.stat().st_size
        
        return total_size 