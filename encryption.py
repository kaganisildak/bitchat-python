import os
import hashlib
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

class EncryptionError(Exception):
    """Encryption-related errors"""
    pass

class EncryptionService:
    def __init__(self):
        # Generate ephemeral keys
        self.private_key = X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        
        self.signing_key = ed25519.Ed25519PrivateKey.generate()
        self.verifying_key = self.signing_key.public_key()
        
        # Generate persistent identity key
        self._identity_key = ed25519.Ed25519PrivateKey.generate()
        self.identity_public = self._identity_key.public_key()
        
        # Storage
        self.peer_public_keys: Dict[str, X25519PublicKey] = {}
        self.peer_signing_keys: Dict[str, ed25519.Ed25519PublicKey] = {}
        self.peer_identity_keys: Dict[str, ed25519.Ed25519PublicKey] = {}
        self.shared_secrets: Dict[str, bytes] = {}
    
    def get_combined_public_key_data(self) -> bytes:
        """Get 96-byte combined public key data"""
        data = bytearray()
        # X25519 public key (32 bytes)
        data.extend(self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ))
        # Ed25519 signing key (32 bytes)
        data.extend(self.verifying_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ))
        # Identity key (32 bytes)
        data.extend(self.identity_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ))
        return bytes(data)
    

        
        # Parse Ed25519 signing key
        try:
            signing_key = ed25519.Ed25519PublicKey.from_public_bytes(signing_key_bytes)
        except Exception:
            raise EncryptionError("Invalid signing key")
        
        # Parse identity key with Android compatibility
        try:
            identity_key = ed25519.Ed25519PublicKey.from_public_bytes(identity_key_bytes)
        except Exception:
            # Android bug compatibility
            print(f"[CRYPTO] Note: Peer {peer_id} appears to be Android (invalid identity key format)")
            identity_key = signing_key
        
        # Store keys
        self.peer_public_keys[peer_id] = public_key
        self.peer_signing_keys[peer_id] = signing_key
        self.peer_identity_keys[peer_id] = identity_key
        
        # Generate shared secret
        shared_secret = self.private_key.exchange(public_key)
        
        # Derive symmetric key using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"bitchat-v1",
            info=b"",
            backend=default_backend()
        )
        symmetric_key = hkdf.derive(shared_secret)
        
        self.shared_secrets[peer_id] = symmetric_key
        print(f"[CRYPTO] Successfully established shared secret with {peer_id}")
    
    def get_peer_identity_key(self, peer_id: str) -> Optional[bytes]:
        """Get peer's identity key bytes"""
        if peer_id in self.peer_identity_keys:
            return self.peer_identity_keys[peer_id].public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        return None
    
    def get_peer_fingerprint(self, peer_id: str) -> Optional[str]:
        """Get SHA256 fingerprint of peer's identity key"""
        key_bytes = self.get_peer_identity_key(peer_id)
        if key_bytes:
            digest = hashlib.sha256(key_bytes).digest()
            return digest[:16].hex()
        return None
    
    def encrypt(self, data: bytes, peer_id: str) -> bytes:
        """Encrypt data for a peer"""
        if peer_id not in self.shared_secrets:
            raise EncryptionError("No shared secret")
        
        aesgcm = AESGCM(self.shared_secrets[peer_id])
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        
        return nonce + ciphertext
    
    def decrypt(self, data: bytes, peer_id: str) -> bytes:
        """Decrypt data from a peer"""
        if len(data) < 12:
            raise EncryptionError("Data too short")
        
        if peer_id not in self.shared_secrets:
            raise EncryptionError("No shared secret")
        
        aesgcm = AESGCM(self.shared_secrets[peer_id])
        nonce = data[:12]
        ciphertext = data[12:]
        
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext
        except Exception:
            raise EncryptionError("Decryption failed")
    
    def sign(self, data: bytes) -> bytes:
        """Sign data"""
        signature = self.signing_key.sign(data)
        return signature
    
    def verify(self, signature: bytes, data: bytes, peer_id: str) -> bool:
        """Verify signature"""
        if peer_id not in self.peer_signing_keys:
            raise EncryptionError("No signing key")
        
        try:
            self.peer_signing_keys[peer_id].verify(signature, data)
            return True
        except Exception:
            return False
    
    @staticmethod
    def derive_channel_key(password: str, channel_name: str) -> bytes:
        """Derive channel key from password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=channel_name.encode(),
            iterations=100_000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    def encrypt_with_key(self, data: bytes, key: bytes) -> bytes:
        """Encrypt with a specific key"""
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext
    
    def decrypt_with_key(self, data: bytes, key: bytes) -> bytes:
        """Decrypt with a specific key"""
        if len(data) < 12:
            raise EncryptionError("Data too short")
        
        aesgcm = AESGCM(key)
        nonce = data[:12]
        ciphertext = data[12:]
        
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext
        except Exception:
            raise EncryptionError("Decryption failed")
    
    def has_peer_key(self, peer_id: str) -> bool:
        """Check if we have a peer's key"""
        return peer_id in self.shared_secrets
    
    def encrypt_for_peer(self, peer_id: str, data: bytes) -> bytes:
        """Encrypt specifically for a peer"""
        return self.encrypt(data, peer_id)

# Export classes and errors
__all__ = ['EncryptionError', 'EncryptionService']