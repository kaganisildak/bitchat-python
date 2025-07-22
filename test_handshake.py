#!/usr/bin/env python3
"""
Test script to reproduce and debug the handshake InvalidTag error
"""

import sys
import traceback
from encryption import EncryptionService, NoiseRole

def test_handshake():
    """Test the handshake between two peers"""
    print("Starting handshake test...")
    
    # Create two encryption services (simulating two peers)
    alice = EncryptionService()
    bob = EncryptionService()
    
    try:
        # Alice initiates handshake (Message 1: -> e)
        print("\n=== Step 1: Alice sends Message 1 ===")
        msg1 = alice.initiate_handshake("bob")
        print(f"Message 1 length: {len(msg1)}, content: {msg1.hex()}")
        
        # Bob processes Message 1 and sends Message 2 (Message 2: <- e, ee, s, es)
        print("\n=== Step 2: Bob processes Message 1 and sends Message 2 ===")
        msg2 = bob.process_handshake_message("alice", msg1)
        print(f"Message 2 length: {len(msg2) if msg2 else 0}, content: {msg2.hex() if msg2 else 'None'}")
        
        # Alice processes Message 2 and sends Message 3 (Message 3: -> s, se)
        print("\n=== Step 3: Alice processes Message 2 and sends Message 3 ===")
        msg3 = alice.process_handshake_message("bob", msg2)
        print(f"Message 3 length: {len(msg3) if msg3 else 0}, content: {msg3.hex() if msg3 else 'None'}")
        
        # Bob processes Message 3 (handshake complete)
        print("\n=== Step 4: Bob processes Message 3 ===")
        final_msg = bob.process_handshake_message("alice", msg3)
        print(f"Final message: {final_msg}")
        
        print("\n=== Handshake completed successfully! ===")
        print(f"Alice has session with Bob: {'bob' in alice.sessions}")
        print(f"Bob has session with Alice: {'alice' in bob.sessions}")
        
        # Test encrypted messaging
        if 'bob' in alice.sessions and 'alice' in bob.sessions:
            print("\n=== Testing encrypted messaging ===")
            test_message = b"Hello from Alice!"
            encrypted = alice.encrypt(test_message, "bob")
            print(f"Encrypted message: {encrypted.hex()}")
            
            decrypted = bob.decrypt_from_peer("alice", encrypted)
            print(f"Decrypted message: {decrypted}")
            print(f"Messages match: {test_message == decrypted}")
        
    except Exception as e:
        print(f"\n=== ERROR OCCURRED ===")
        print(f"Error: {e}")
        print(f"Error type: {type(e).__name__}")
        print("Full traceback:")
        traceback.print_exc()
        return False
    
    return True

if __name__ == "__main__":
    success = test_handshake()
    sys.exit(0 if success else 1)
