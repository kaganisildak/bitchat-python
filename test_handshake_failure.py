#!/usr/bin/env python3
"""
Enhanced test script to reproduce handshake InvalidTag error
by simulating real-world conditions
"""

import sys
import traceback
from encryption import EncryptionService, NoiseRole
from cryptography.exceptions import InvalidTag

def test_handshake_with_peer_id_mismatch():
    """Test handshake where peer IDs don't match between parties"""
    print("=== Testing handshake with peer ID mismatch ===")
    
    alice = EncryptionService()
    bob = EncryptionService()
    
    try:
        # Alice thinks she's talking to "bob", but Bob thinks Alice is "alice123"
        msg1 = alice.initiate_handshake("bob")
        msg2 = bob.process_handshake_message("alice123", msg1)  # Wrong peer ID
        msg3 = alice.process_handshake_message("bob", msg2)
        final_msg = bob.process_handshake_message("alice123", msg3)  # Wrong peer ID
        
        print("❌ Expected failure but succeeded")
        return False
        
    except Exception as e:
        print(f"✅ Failed as expected: {type(e).__name__}: {e}")
        return True

def test_handshake_with_state_reset():
    """Test handshake where one peer resets state mid-handshake"""
    print("\n=== Testing handshake with state reset ===")
    
    alice = EncryptionService()
    bob = EncryptionService()
    
    try:
        # Normal start
        msg1 = alice.initiate_handshake("bob")
        msg2 = bob.process_handshake_message("alice", msg1)
        
        # Bob resets state (simulating restart or memory issue)
        if "alice" in bob.handshake_states:
            del bob.handshake_states["alice"]
        
        # Alice tries to continue handshake
        msg3 = alice.process_handshake_message("bob", msg2)
        final_msg = bob.process_handshake_message("alice", msg3)  # Bob has no state
        
        print("❌ Expected failure but succeeded")
        return False
        
    except Exception as e:
        print(f"✅ Failed as expected: {type(e).__name__}: {e}")
        return True

def test_handshake_with_corrupted_message():
    """Test handshake with corrupted message"""
    print("\n=== Testing handshake with corrupted message ===")
    
    alice = EncryptionService()
    bob = EncryptionService()
    
    try:
        # Normal start
        msg1 = alice.initiate_handshake("bob")
        msg2 = bob.process_handshake_message("alice", msg1)
        
        # Corrupt one byte in message 2
        corrupted_msg2 = bytearray(msg2)
        if len(corrupted_msg2) > 50:
            corrupted_msg2[50] ^= 0xFF  # Flip all bits in one byte
        
        # Alice tries to process corrupted message
        msg3 = alice.process_handshake_message("bob", bytes(corrupted_msg2))
        
        print("❌ Expected failure but succeeded")
        return False
        
    except Exception as e:
        print(f"✅ Failed as expected: {type(e).__name__}: {e}")
        if isinstance(e.__cause__, InvalidTag):
            print("   └─ Root cause: InvalidTag (expected for corrupted message)")
        return True

def test_handshake_with_message_replay():
    """Test handshake with message replay attack"""
    print("\n=== Testing handshake with message replay ===")
    
    alice = EncryptionService()
    bob = EncryptionService()
    
    try:
        # Complete a normal handshake
        msg1 = alice.initiate_handshake("bob")
        msg2 = bob.process_handshake_message("alice", msg1)
        msg3 = alice.process_handshake_message("bob", msg2)
        final_msg = bob.process_handshake_message("alice", msg3)
        
        print(f"✅ First handshake completed successfully")
        
        # Now try to replay msg2 (should fail because handshake is complete)
        alice.initiate_handshake("bob")  # Start new handshake
        response = alice.process_handshake_message("bob", msg2)  # Replay old message
        
        print("❌ Expected failure but succeeded")
        return False
        
    except Exception as e:
        print(f"✅ Failed as expected: {type(e).__name__}: {e}")
        return True

def test_handshake_with_wrong_pattern_order():
    """Test handshake with messages in wrong order"""
    print("\n=== Testing handshake with wrong pattern order ===")
    
    alice = EncryptionService()
    bob = EncryptionService()
    charlie = EncryptionService()
    
    try:
        # Alice and Bob start handshake
        msg1_ab = alice.initiate_handshake("bob")
        msg2_ba = bob.process_handshake_message("alice", msg1_ab)
        
        # Charlie and Bob start separate handshake
        msg1_cb = charlie.initiate_handshake("bob")
        msg2_bc = bob.process_handshake_message("charlie", msg1_cb)
        
        # Now Bob sends Charlie's response to Alice (wrong peer's message)
        msg3 = alice.process_handshake_message("bob", msg2_bc)  # Wrong message
        
        print("❌ Expected failure but succeeded")
        return False
        
    except Exception as e:
        print(f"✅ Failed as expected: {type(e).__name__}: {e}")
        return True

def main():
    """Run all handshake failure tests"""
    print("Running enhanced handshake tests...\n")
    
    tests = [
        test_handshake_with_peer_id_mismatch,
        test_handshake_with_state_reset,
        test_handshake_with_corrupted_message,
        test_handshake_with_message_replay,
        test_handshake_with_wrong_pattern_order
    ]
    
    passed = 0
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"❌ Test {test.__name__} crashed: {e}")
            traceback.print_exc()
    
    print(f"\n=== Results ===")
    print(f"Passed: {passed}/{len(tests)} tests")
    print("All tests should pass by failing as expected")
    
    return passed == len(tests)

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
