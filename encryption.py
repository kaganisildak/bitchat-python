
import os
import hashlib
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import time

# --- Errors ---
class EncryptionError(Exception):
    pass

# --- Protocol Constants ---
NOISE_PROTOCOL_NAME = b"Noise_XX_25519_ChaChaPoly_SHA256"
HASH_LEN = 32
KEY_LEN = 32

# --- Noise Protocol Implementation ---

class CipherState:
    def __init__(self):
        self.key = None
        self.nonce = 0

    def initialize_key(self, key: bytes):
        self.key = key
        self.nonce = 0

    def has_key(self) -> bool:
        return self.key is not None

    def encrypt(self, plaintext: bytes, ad: bytes) -> bytes:
        if not self.has_key():
            return plaintext
        
        chacha = ChaCha20Poly1305(self.key)
        nonce_bytes = self.nonce.to_bytes(12, 'little')
        self.nonce += 1
        return chacha.encrypt(nonce_bytes, plaintext, ad)

    def decrypt(self, ciphertext: bytes, ad: bytes) -> bytes:
        if not self.has_key():
            return ciphertext
            
        chacha = ChaCha20Poly1305(self.key)
        nonce_bytes = self.nonce.to_bytes(12, 'little')
        self.nonce += 1
        return chacha.decrypt(nonce_bytes, ciphertext, ad)

class SymmetricState:
    def __init__(self, protocol_name: bytes):
        self.cipher_state = CipherState()
        h = hashlib.sha256(protocol_name).digest()
        self.h = h
        self.ck = h

    def _hkdf(self, ck: bytes, ikm: bytes, num_outputs: int) -> List[bytes]:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=num_outputs * HASH_LEN,
            salt=ck,
            info=b'',
            backend=default_backend()
        )
        okm = hkdf.derive(ikm)
        return [okm[i*HASH_LEN:(i+1)*HASH_LEN] for i in range(num_outputs)]

    def mix_key(self, ikm: bytes):
        self.ck, temp_k = self._hkdf(self.ck, ikm, 2)
        self.cipher_state.initialize_key(temp_k)

    def mix_hash(self, data: bytes):
        hasher = hashlib.sha256()
        hasher.update(self.h)
        hasher.update(data)
        self.h = hasher.digest()

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        ciphertext = self.cipher_state.encrypt(plaintext, self.h)
        self.mix_hash(ciphertext)
        return ciphertext

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        plaintext = self.cipher_state.decrypt(ciphertext, self.h)
        self.mix_hash(ciphertext)
        return plaintext

    def split(self) -> Tuple[CipherState, CipherState]:
        k1, k2 = self._hkdf(self.ck, b'', 2)
        c1 = CipherState()
        c1.initialize_key(k1)
        c2 = CipherState()
        c2.initialize_key(k2)
        return c1, c2

class HandshakeState:
    def __init__(self, role: str, local_s: x25519.X25519PrivateKey, remote_s: Optional[x25519.X25519PublicKey] = None):
        self.role = role
        self.symmetric_state = SymmetricState(NOISE_PROTOCOL_NAME)
        
        self.local_s = local_s
        self.local_e = None
        self.remote_s = remote_s
        self.remote_e = None

        self.message_patterns = [
            ['e'],
            ['e', 'ee', 's', 'es'],
            ['s', 'se']
        ]
        self.pattern_idx = 0

    def _dh(self, priv, pub) -> bytes:
        return priv.exchange(pub)

    def write_message(self, payload: bytes) -> bytes:
        message_buffer = bytearray()
        patterns = self.message_patterns[self.pattern_idx]

        for token in patterns:
            if token == 'e':
                self.local_e = x25519.X25519PrivateKey.generate()
                e_pub_bytes = self.local_e.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
                message_buffer.extend(e_pub_bytes)
                self.symmetric_state.mix_hash(e_pub_bytes)
            elif token == 's':
                s_pub_bytes = self.local_s.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
                encrypted_s = self.symmetric_state.encrypt_and_hash(s_pub_bytes)
                message_buffer.extend(encrypted_s)
            elif token == 'ee':
                self.symmetric_state.mix_key(self._dh(self.local_e, self.remote_e))
            elif token == 'es':
                if self.role == 'initiator':
                    self.symmetric_state.mix_key(self._dh(self.local_e, self.remote_s))
                else:
                    self.symmetric_state.mix_key(self._dh(self.local_s, self.remote_e))
            elif token == 'se':
                if self.role == 'initiator':
                    self.symmetric_state.mix_key(self._dh(self.local_s, self.remote_e))
                else:
                    self.symmetric_state.mix_key(self._dh(self.local_e, self.remote_s))

        self.pattern_idx += 1
        message_buffer.extend(self.symmetric_state.encrypt_and_hash(payload))
        return bytes(message_buffer)

    def read_message(self, message: bytes) -> bytes:
        message_buffer = bytearray(message)
        patterns = self.message_patterns[self.pattern_idx]

        for token in patterns:
            if token == 'e':
                e_bytes = message_buffer[:KEY_LEN]
                del message_buffer[:KEY_LEN]
                self.remote_e = x25519.X25519PublicKey.from_public_bytes(e_bytes)
                self.symmetric_state.mix_hash(e_bytes)
            elif token == 's':
                key_len = KEY_LEN + (16 if self.symmetric_state.cipher_state.has_key() else 0)
                encrypted_s = message_buffer[:key_len]
                del message_buffer[:key_len]
                s_bytes = self.symmetric_state.decrypt_and_hash(encrypted_s)
                self.remote_s = x25519.X25519PublicKey.from_public_bytes(s_bytes)
            elif token == 'ee':
                self.symmetric_state.mix_key(self._dh(self.local_e, self.remote_e))
            elif token == 'es':
                if self.role == 'initiator':
                    self.symmetric_state.mix_key(self._dh(self.local_e, self.remote_s))
                else:
                    self.symmetric_state.mix_key(self._dh(self.local_s, self.remote_e))
            elif token == 'se':
                if self.role == 'initiator':
                    self.symmetric_state.mix_key(self._dh(self.local_s, self.remote_e))
                else:
                    self.symmetric_state.mix_key(self._dh(self.local_e, self.remote_s))
        
        self.pattern_idx += 1
        return self.symmetric_state.decrypt_and_hash(bytes(message_buffer))

    def is_handshake_complete(self) -> bool:
        return self.pattern_idx >= len(self.message_patterns)

# --- Session Management ---

class NoiseSession:
    def __init__(self, peer_id: str, role: str, local_static_key: x25519.X25519PrivateKey):
        self.peer_id = peer_id
        self.role = role
        self.local_static_key = local_static_key
        self.remote_static_key = None
        self.handshake_state = HandshakeState(role, local_static_key)
        self.send_cipher = None
        self.receive_cipher = None
        self.is_established = False

    def start_handshake(self) -> bytes:
        if self.role != 'initiator':
            raise EncryptionError("Only initiator can start handshake")
        return self.handshake_state.write_message(b'')

    def process_handshake_message(self, message: bytes) -> Optional[bytes]:
        _ = self.handshake_state.read_message(message)
        
        if self.handshake_state.is_handshake_complete():
            self._finalize_handshake()
            return None
        else:
            response = self.handshake_state.write_message(b'')
            if self.handshake_state.is_handshake_complete():
                self._finalize_handshake()
            return response

    def _finalize_handshake(self):
        c1, c2 = self.handshake_state.symmetric_state.split()
        if self.role == 'initiator':
            self.send_cipher, self.receive_cipher = c1, c2
        else:
            self.send_cipher, self.receive_cipher = c2, c1
        self.remote_static_key = self.handshake_state.remote_s
        self.is_established = True
        self.handshake_state = None # No longer needed

    def encrypt(self, plaintext: bytes) -> bytes:
        if not self.is_established:
            raise EncryptionError("Session not established")
        return self.send_cipher.encrypt(plaintext, b'')

    def decrypt(self, ciphertext: bytes) -> bytes:
        if not self.is_established:
            raise EncryptionError("Session not established")
        return self.receive_cipher.decrypt(ciphertext, b'')

class NoiseSessionManager:
    def __init__(self, local_static_key: x25519.X25519PrivateKey):
        self.local_static_key = local_static_key
        self.sessions: Dict[str, NoiseSession] = {}

    def get_session(self, peer_id: str, role: str = 'initiator') -> NoiseSession:
        if peer_id not in self.sessions:
            self.sessions[peer_id] = NoiseSession(peer_id, role, self.local_static_key)
        return self.sessions[peer_id]

    def remove_session(self, peer_id: str):
        if peer_id in self.sessions:
            del self.sessions[peer_id]

# --- Channel Encryption ---

class NoiseChannelKeyRotation:
    EPOCH_DURATION = 24 * 60 * 60  # 24 hours

    def __init__(self):
        self.channel_epochs: Dict[str, List[Dict]] = {}

    def get_current_key(self, channel: str, base_password: str, creator_fingerprint: str) -> bytes:
        now = int(time.time())
        epoch_num = now // self.EPOCH_DURATION
        return self._derive_epoch_key(base_password, channel, creator_fingerprint, epoch_num)

    def get_valid_keys_for_decryption(self, channel: str, base_password: str, creator_fingerprint: str) -> List[bytes]:
        now = int(time.time())
        current_epoch_num = now // self.EPOCH_DURATION
        # Check current and previous epoch for late messages
        return [
            self._derive_epoch_key(base_password, channel, creator_fingerprint, epoch_num)
            for epoch_num in [current_epoch_num, current_epoch_num - 1]
        ]

    def _derive_epoch_key(self, base_password: str, channel: str, creator_fingerprint: str, epoch_number: int) -> bytes:
        salt = f"{channel}-{creator_fingerprint}-epoch-{epoch_number}".encode('utf-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=210_000,
            backend=default_backend()
        )
        return kdf.derive(base_password.encode('utf-8'))

class ChannelEncryption:
    def __init__(self):
        self.channel_keys: Dict[str, bytes] = {}
        self.key_rotation = NoiseChannelKeyRotation()

    def set_channel_password(self, password: str, channel: str, creator_fingerprint: str):
        # The "base password" is now used for key rotation, not directly for encryption
        pass

    def encrypt_channel_message(self, message: str, channel: str, password: str, creator_fingerprint: str) -> bytes:
        key = self.key_rotation.get_current_key(channel, password, creator_fingerprint)
        chacha = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        return nonce + chacha.encrypt(nonce, message.encode('utf-8'), None)

    def decrypt_channel_message(self, encrypted_data: bytes, channel: str, password: str, creator_fingerprint: str) -> Optional[str]:
        keys = self.key_rotation.get_valid_keys_for_decryption(channel, password, creator_fingerprint)
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]

        for key in keys:
            try:
                chacha = ChaCha20Poly1305(key)
                decrypted_data = chacha.decrypt(nonce, ciphertext, None)
                return decrypted_data.decode('utf-8')
            except Exception:
                continue
        return None

# --- Main Service ---

class EncryptionService:
    def __init__(self):
        self.local_static_key = x25519.X25519PrivateKey.generate()
        self.session_manager = NoiseSessionManager(self.local_static_key)
        self.channel_encryption = ChannelEncryption()

    def get_public_key_bytes(self) -> bytes:
        return self.local_static_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
    def get_fingerprint(self) -> str:
        pk_bytes = self.get_public_key_bytes()
        return hashlib.sha256(pk_bytes).hexdigest()

    def get_peer_fingerprint(self, peer_id: str) -> Optional[str]:
        session = self.session_manager.get_session(peer_id, role='responder')
        if session and session.is_established and session.remote_static_key:
            pk_bytes = session.remote_static_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            return hashlib.sha256(pk_bytes).hexdigest()
        return None

    # Peer-to-peer session methods
    def initiate_handshake(self, peer_id: str) -> bytes:
        session = self.session_manager.get_session(peer_id, role='initiator')
        return session.start_handshake()

    def handle_handshake_message(self, peer_id: str, message: bytes) -> Optional[bytes]:
        # If we are the responder, we need to create a session
        session = self.session_manager.get_session(peer_id, role='responder')
        return session.process_handshake_message(message)

    def encrypt_for_peer(self, peer_id: str, data: bytes) -> bytes:
        session = self.session_manager.get_session(peer_id)
        return session.encrypt(data)

    def decrypt_from_peer(self, peer_id: str, data: bytes) -> bytes:
        session = self.session_manager.get_session(peer_id)
        return session.decrypt(data)
        
    def is_session_established(self, peer_id: str) -> bool:
        if peer_id in self.session_manager.sessions:
            return self.session_manager.sessions[peer_id].is_established
        return False

    # Channel encryption methods
    def encrypt_for_channel(self, message: str, channel: str, password: str, creator_fingerprint: str) -> bytes:
        return self.channel_encryption.encrypt_channel_message(message, channel, password, creator_fingerprint)

    def decrypt_from_channel(self, data: bytes, channel: str, password:str, creator_fingerprint: str) -> Optional[str]:
        return self.channel_encryption.decrypt_channel_message(data, channel, password, creator_fingerprint)

__all__ = ['EncryptionService', 'EncryptionError']
