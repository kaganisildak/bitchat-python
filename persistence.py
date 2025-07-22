import os
import json
import hashlib
from pathlib import Path
from typing import Dict, Set, List, Optional
from dataclasses import dataclass, field, asdict
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ed25519

@dataclass
class EncryptedPassword:
    nonce: List[int]
    ciphertext: List[int]

@dataclass
class AppState:
    nickname: Optional[str] = None
    blocked_peers: Set[str] = field(default_factory=set)
    channel_creators: Dict[str, str] = field(default_factory=dict)
    joined_channels: List[str] = field(default_factory=list)
    password_protected_channels: Set[str] = field(default_factory=set)
    channel_key_commitments: Dict[str, str] = field(default_factory=dict)
    favorites: Set[str] = field(default_factory=set)
    identity_key: Optional[List[int]] = None
    encrypted_channel_passwords: Dict[str, EncryptedPassword] = field(default_factory=dict)

def get_state_file_path() -> Path:
    """Get the state file path"""
    home = Path.home()
    bitchat_dir = home / ".bitchatxxk"
    bitchat_dir.mkdir(exist_ok=True)
    return bitchat_dir / "state.json"

class AppStateEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        if isinstance(obj, EncryptedPassword):
            return {"nonce": obj.nonce, "ciphertext": obj.ciphertext}
        return super().default(obj)

def load_state() -> AppState:
    """Load app state from disk"""
    path = get_state_file_path()
    
    if path.exists():
        try:
            with open(path, 'r') as f:
                data = json.load(f)
                
                # Convert lists back to sets
                if 'blocked_peers' in data:
                    data['blocked_peers'] = set(data['blocked_peers'])
                if 'password_protected_channels' in data:
                    data['password_protected_channels'] = set(data['password_protected_channels'])
                if 'favorites' in data:
                    data['favorites'] = set(data['favorites'])
                
                # Convert encrypted passwords
                if 'encrypted_channel_passwords' in data:
                    encrypted_passwords = {}
                    for channel, enc_data in data['encrypted_channel_passwords'].items():
                        encrypted_passwords[channel] = EncryptedPassword(
                            nonce=enc_data['nonce'],
                            ciphertext=enc_data['ciphertext']
                        )
                    data['encrypted_channel_passwords'] = encrypted_passwords
                
                state = AppState(**data)
        except Exception as e:
            print(f"Warning: Could not parse state file: {e}")
            state = AppState()
    else:
        state = AppState()
    
    # Generate identity key if not present
    if state.identity_key is None:
        signing_key = ed25519.Ed25519PrivateKey.generate()
        state.identity_key = list(signing_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ))
        save_state(state)
    
    return state

def save_state(state: AppState) -> None:
    """Save app state to disk"""
    path = get_state_file_path()
    
    # Convert to dict for JSON serialization
    data = {
        'nickname': state.nickname,
        'blocked_peers': list(state.blocked_peers),
        'channel_creators': state.channel_creators,
        'joined_channels': state.joined_channels,
        'password_protected_channels': list(state.password_protected_channels),
        'channel_key_commitments': state.channel_key_commitments,
        'favorites': list(state.favorites),
        'identity_key': state.identity_key,
        'encrypted_channel_passwords': {
            channel: {'nonce': ep.nonce, 'ciphertext': ep.ciphertext}
            for channel, ep in state.encrypted_channel_passwords.items()
        }
    }
    
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)

def derive_encryption_key(identity_key: bytes) -> bytes:
    """Derive AES key from identity key"""
    h = hashlib.sha256()
    h.update(b"bitchat-password-encryption")
    h.update(identity_key)
    return h.digest()

def encrypt_password(password: str, identity_key: List[int]) -> EncryptedPassword:
    """Encrypt a password using the identity key"""
    identity_key_bytes = bytes(identity_key)
    key = derive_encryption_key(identity_key_bytes)
    
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, password.encode(), None)
    
    return EncryptedPassword(
        nonce=list(nonce),
        ciphertext=list(ciphertext)
    )

def decrypt_password(encrypted: EncryptedPassword, identity_key: List[int]) -> str:
    """Decrypt a password using the identity key"""
    identity_key_bytes = bytes(identity_key)
    key = derive_encryption_key(identity_key_bytes)
    
    aesgcm = AESGCM(key)
    nonce = bytes(encrypted.nonce)
    ciphertext = bytes(encrypted.ciphertext)
    
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()

# Export classes and functions
__all__ = ['EncryptedPassword', 'AppState', 'get_state_file_path', 'load_state', 'save_state', 
           'encrypt_password', 'decrypt_password']