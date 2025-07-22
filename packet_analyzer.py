#!/usr/bin/env python3
"""
Packet analyzer to decode BitChat protocol packets from hex strings
"""

import struct
import sys
import argparse
import time
from enum import IntEnum
from typing import Optional

class MessageType(IntEnum):
    ANNOUNCE = 0x01
    KEY_EXCHANGE = 0x02
    LEAVE = 0x03
    MESSAGE = 0x04
    FRAGMENT_START = 0x05
    FRAGMENT_CONTINUE = 0x06
    FRAGMENT_END = 0x07
    DELIVERY_ACK = 0x08
    CHANNEL_ANNOUNCE = 0x09
    NOISE_HANDSHAKE_INIT = 0x10
    NOISE_HANDSHAKE_RESP = 0x11
    NOISE_ENCRYPTED = 0x12
    NOISE_IDENTITY_ANNOUNCE = 0x13

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

def analyze_packet(hex_data: str, label: str = ""):
    """Analyze a packet from hex string"""
    print(f"\n{'='*60}")
    print(f"ANALYZING: {label}")
    print(f"{'='*60}")
    print(f"Raw hex: {hex_data}")
    print(f"Length: {len(hex_data)//2} bytes")
    
    try:
        data = bytes.fromhex(hex_data)
        
        if len(data) < 13:
            print("ERROR: Packet too small for header")
            return
        
        offset = 0
        
        # Header analysis
        print(f"\n--- HEADER ANALYSIS ---")
        version = data[offset]; offset += 1
        print(f"Version: {version} (0x{version:02x})")
        
        msg_type_val = data[offset]; offset += 1
        try:
            msg_type = MessageType(msg_type_val)
            print(f"Type: {msg_type.name} ({msg_type_val}, 0x{msg_type_val:02x})")
        except ValueError:
            print(f"Type: UNKNOWN ({msg_type_val}, 0x{msg_type_val:02x})")
        
        ttl = data[offset]; offset += 1
        print(f"TTL: {ttl}")
        
        # Timestamp (8 bytes, big-endian)
        timestamp_bytes = data[offset:offset+8]
        timestamp = struct.unpack('>Q', timestamp_bytes)[0]
        offset += 8
        print(f"Timestamp: {timestamp} (0x{timestamp:016x})")
        
        # Flags
        flags = data[offset]; offset += 1
        has_recipient = (flags & FLAG_HAS_RECIPIENT) != 0
        has_signature = (flags & FLAG_HAS_SIGNATURE) != 0
        is_compressed = (flags & FLAG_IS_COMPRESSED) != 0
        print(f"Flags: 0x{flags:02x}")
        print(f"  - Has Recipient: {has_recipient}")
        print(f"  - Has Signature: {has_signature}")
        print(f"  - Is Compressed: {is_compressed}")
        
        # Payload length
        payload_len = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        print(f"Payload Length: {payload_len}")
        
        # Sender ID
        sender_id_raw = data[offset:offset+8]
        sender_id = sender_id_raw.rstrip(b'\x00')  # Remove null padding
        offset += 8
        print(f"Sender ID: {sender_id.hex()} (raw: {sender_id_raw.hex()})")
        
        # Recipient ID
        if has_recipient:
            recipient_id_raw = data[offset:offset+8]
            recipient_id = recipient_id_raw.rstrip(b'\x00')
            offset += 8
            print(f"Recipient ID: {recipient_id.hex()} (raw: {recipient_id_raw.hex()})")
        else:
            print("Recipient ID: None")
        
        # Calculate expected minimum size
        expected_min_size = 13 + 8  # header + sender
        if has_recipient:
            expected_min_size += 8
        expected_min_size += payload_len
        if has_signature:
            expected_min_size += 64
        
        print(f"\nExpected minimum size: {expected_min_size} bytes")
        print(f"Actual size: {len(data)} bytes")
        
        # Payload
        if offset + payload_len <= len(data):
            payload = data[offset:offset + payload_len]
            offset += payload_len
            print(f"\n--- PAYLOAD ANALYSIS ---")
            print(f"Payload ({payload_len} bytes): {payload.hex()}")
            
            # Try to decode message payload if it's a message type
            if msg_type_val == MessageType.MESSAGE and len(payload) > 0:
                try:
                    analyze_message_payload(payload)
                except Exception as e:
                    print(f"Error analyzing message payload: {e}")
            elif msg_type_val in [MessageType.NOISE_HANDSHAKE_INIT, MessageType.NOISE_HANDSHAKE_RESP]:
                print("This is a Noise handshake packet")
                if len(payload) >= 32:
                    print(f"Likely contains public key: {payload[:32].hex()}")
                    if len(payload) > 32:
                        print(f"Additional data: {payload[32:].hex()}")
            elif msg_type_val == MessageType.NOISE_ENCRYPTED:
                print("This is a Noise encrypted packet")
                print(f"Encrypted payload: {payload.hex()}")
        else:
            print(f"ERROR: Not enough data for payload (need {payload_len}, have {len(data) - offset})")
        
        # Signature
        if has_signature:
            if offset + 64 <= len(data):
                signature = data[offset:offset + 64]
                print(f"\n--- SIGNATURE ---")
                print(f"Signature: {signature.hex()}")
            else:
                print("ERROR: Not enough data for signature")
        
        # Padding analysis
        remaining = len(data) - offset
        if remaining > 0:
            padding = data[offset:]
            print(f"\n--- PADDING/EXTRA DATA ---")
            print(f"Remaining {remaining} bytes: {padding.hex()}")
            # Check if it's all zeros (padding) or contains data
            if all(b == 0 for b in padding):
                print("Appears to be null padding")
            else:
                print("Contains non-zero data - may be actual content or different padding")
                
    except Exception as e:
        print(f"ERROR analyzing packet: {e}")
        import traceback
        traceback.print_exc()

def quick_analyze_packet(hex_data: str, label: str = ""):
    """Quick analysis showing only header information"""
    try:
        data = bytes.fromhex(hex_data.replace(' ', ''))
        
        if len(data) < 13:
            print(f"{label}: ERROR - Packet too small ({len(data)} bytes)")
            return
        
        # Quick header parse
        version = data[0]
        msg_type_val = data[1]
        ttl = data[2]
        timestamp = struct.unpack('>Q', data[3:11])[0]
        flags = data[11]
        payload_len = struct.unpack('>H', data[12:14])[0]
        
        try:
            msg_type = MessageType(msg_type_val)
            type_name = msg_type.name
        except ValueError:
            type_name = f"UNKNOWN(0x{msg_type_val:02x})"
        
        has_recipient = (flags & FLAG_HAS_RECIPIENT) != 0
        has_signature = (flags & FLAG_HAS_SIGNATURE) != 0
        
        print(f"{label}: {type_name} | {len(data)}B | TTL:{ttl} | Payload:{payload_len}B | Flags:0x{flags:02x} | {'R' if has_recipient else '-'}{'S' if has_signature else '-'}")
        
    except Exception as e:
        print(f"{label}: ERROR - {e}")

def process_packet(hex_data: str, label: str, args):
    """Process a packet with options for quick mode and export"""
    # Clean hex data
    clean_hex = hex_data.replace(' ', '').replace('\n', '').replace('\t', '')
    
    # Export if requested
    if args.export:
        try:
            packet_data = bytes.fromhex(clean_hex)
            export_packet_to_file(packet_data, args.export, label)
        except Exception as e:
            print(f"Export error for {label}: {e}")
    
    # Analyze
    if args.quick:
        quick_analyze_packet(clean_hex, label)
    else:
        analyze_packet(clean_hex, label)

def analyze_message_payload(payload: bytes):
    """Analyze message payload structure"""
    print(f"\n--- MESSAGE PAYLOAD ANALYSIS ---")
    
    if len(payload) < 11:  # minimum: flags(1) + timestamp(8) + id_len(1) + sender_len(1)
        print("Payload too small for message")
        return
    
    offset = 0
    
    # Flags
    flags = payload[offset]; offset += 1
    is_relay = (flags & MSG_FLAG_IS_RELAY) != 0
    is_private = (flags & MSG_FLAG_IS_PRIVATE) != 0
    has_original_sender = (flags & MSG_FLAG_HAS_ORIGINAL_SENDER) != 0
    has_recipient_nickname = (flags & MSG_FLAG_HAS_RECIPIENT_NICKNAME) != 0
    has_sender_peer_id = (flags & MSG_FLAG_HAS_SENDER_PEER_ID) != 0
    has_mentions = (flags & MSG_FLAG_HAS_MENTIONS) != 0
    has_channel = (flags & MSG_FLAG_HAS_CHANNEL) != 0
    is_encrypted = (flags & MSG_FLAG_IS_ENCRYPTED) != 0
    
    print(f"Message Flags: 0x{flags:02x}")
    print(f"  - Is Relay: {is_relay}")
    print(f"  - Is Private: {is_private}")
    print(f"  - Has Original Sender: {has_original_sender}")
    print(f"  - Has Recipient Nickname: {has_recipient_nickname}")
    print(f"  - Has Sender Peer ID: {has_sender_peer_id}")
    print(f"  - Has Mentions: {has_mentions}")
    print(f"  - Has Channel: {has_channel}")
    print(f"  - Is Encrypted: {is_encrypted}")
    
    # Timestamp
    if offset + 8 <= len(payload):
        timestamp_ms = struct.unpack('>Q', payload[offset:offset+8])[0]
        offset += 8
        print(f"Timestamp: {timestamp_ms} ms")
    else:
        print("ERROR: Not enough data for timestamp")
        return
    
    # ID
    if offset < len(payload):
        id_len = payload[offset]; offset += 1
        if offset + id_len <= len(payload):
            id_data = payload[offset:offset + id_len]
            message_id = id_data.decode('utf-8', errors='replace')
            offset += id_len
            print(f"Message ID: '{message_id}' ({id_len} bytes)")
        else:
            print(f"ERROR: Not enough data for message ID (need {id_len})")
            return
    
    # Sender
    if offset < len(payload):
        sender_len = payload[offset]; offset += 1
        if offset + sender_len <= len(payload):
            sender_data = payload[offset:offset + sender_len]
            sender = sender_data.decode('utf-8', errors='replace')
            offset += sender_len
            print(f"Sender: '{sender}' ({sender_len} bytes)")
        else:
            print(f"ERROR: Not enough data for sender (need {sender_len})")
            return
    
    # Content
    if offset + 2 <= len(payload):
        content_len = struct.unpack('>H', payload[offset:offset+2])[0]
        offset += 2
        if offset + content_len <= len(payload):
            content_data = payload[offset:offset + content_len]
            offset += content_len
            if is_encrypted:
                print(f"Encrypted Content: {content_data.hex()} ({content_len} bytes)")
            else:
                try:
                    content = content_data.decode('utf-8', errors='replace')
                    print(f"Content: '{content}' ({content_len} bytes)")
                except:
                    print(f"Content (raw): {content_data.hex()} ({content_len} bytes)")
        else:
            print(f"ERROR: Not enough data for content (need {content_len})")
            return
    
    # Optional fields would continue here...
    remaining = len(payload) - offset
    if remaining > 0:
        print(f"Remaining payload data: {payload[offset:].hex()} ({remaining} bytes)")

def export_packet_to_file(packet_data: bytes, filename: str, label: str = ""):
    """Export packet data to a file in hex format"""
    try:
        with open(filename, 'a') as f:
            if label:
                f.write(f"# {label}\n")
            f.write(f"{packet_data.hex()}\n")
        print(f"Packet exported to {filename}")
    except Exception as e:
        print(f"Error exporting packet: {e}")

def packet_capture_hook(packet_data: bytes, direction: str, peer_id: str = ""):
    """Hook function to capture packets from BitChat"""
    timestamp = struct.pack('>Q', int(time.time() * 1000))
    label = f"{direction} - {peer_id} - {timestamp.hex()}"
    
    # Print basic info
    print(f"\n[PACKET CAPTURE] {label}")
    print(f"Size: {len(packet_data)} bytes")
    print(f"Hex: {packet_data.hex()}")
    
    # Auto-export if requested
    if hasattr(packet_capture_hook, 'export_file') and packet_capture_hook.export_file:
        export_packet_to_file(packet_data, packet_capture_hook.export_file, label)

def main():
    parser = argparse.ArgumentParser(description='BitChat Packet Analyzer')
    parser.add_argument('--hex', '-x', type=str, help='Analyze a single hex string')
    parser.add_argument('--file', '-f', type=str, help='Read hex strings from file (one per line)')
    parser.add_argument('--capture', '-c', action='store_true', help='Capture packets from stdin')
    parser.add_argument('--examples', '-e', action='store_true', help='Analyze example packets')
    parser.add_argument('--export', type=str, help='Export analyzed packets to file')
    parser.add_argument('--quick', '-q', action='store_true', help='Quick analysis (header only)')
    
    args = parser.parse_args()
    
    print("BITCHAT PACKET ANALYSIS")
    print("=" * 60)
    
    if args.hex:
        # Analyze single hex string
        process_packet(args.hex, "Command line input", args)
        
    elif args.file:
        # Read from file
        try:
            with open(args.file, 'r') as f:
                for i, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):  # Skip empty lines and comments
                        process_packet(line, f"File line {i}", args)
        except FileNotFoundError:
            print(f"Error: File '{args.file}' not found")
            sys.exit(1)
        except Exception as e:
            print(f"Error reading file: {e}")
            sys.exit(1)
            
    elif args.capture:
        # Read from stdin
        print("Enter hex strings (one per line, Ctrl+C to exit):")
        try:
            counter = 1
            while True:
                try:
                    line = input(f"Packet {counter}: ").strip()
                    if line:
                        process_packet(line, f"Stdin packet {counter}", args)
                        counter += 1
                except EOFError:
                    break
        except KeyboardInterrupt:
            print("\nExiting...")
            
    elif args.examples:
        # Show example packets (original behavior)
        process_packet(
            "011307000001981ac0784b0100ec3bb0d753fe78374fffffffffffffffff7b22706565724944223a",
            "Example: iOS receiving our data #1", args
        )
        
        process_packet(
            "011003000001981ac0784d0100203bb0d753fe78374ff4e71def1abf2826a21f674c37215383407a1967ae95a4d4fe0c19123f845ed7e1e6291c21858022",
            "Example: iOS receiving our data #2", args
        )
        
        process_packet(
            "011003000001981abfdf7d0100207ab96ef5b7f14188f4e71def1abf2826494173b8be57a11311dd8e538f5dbcccd85f14333e77b75f79e44a1fe8fcfe64",
            "Example: Our sending to iOS", args
        )
        
        process_packet(
            "011103000001981abfdfc9010060f4e71def1abf28267ab96ef5b7f14188a492da2308b3c085657cbabdb8401f7e10e82881321249a61b30ec1a4f038c6f0c16da2e0634ac1e47404bac9b61d5583418b2c48061288588b750c8678ea13673fa4f4b2325945575683094719dd4e134777476550a5547531f5a170fb0981bd6d68b445a780e4ccfa6a4aa057b034bba9668ebcb68650d0cbe3552ac999bc6fe49e943a4de33646bcd18b0a34d3dd8e3265038a7ef35fcf45166c80cd461f6604a40e3b0bc0911f50ef52564f1f657000bdbcb383aae27174f54b561c50ae97d510cb07ad1c07e8ffb079688b9ce590831125c0f14257702b2be8f56996eb69c82",
            "Example: iOS sending to us", args
        )
    else:
        # Default: show help
        parser.print_help()
        print("\nExamples:")
        print("  python3 packet_analyzer.py --hex '011307000001981ac0784b0100ec...'")
        print("  python3 packet_analyzer.py --file packets.txt --quick")
        print("  python3 packet_analyzer.py --capture --export captured_packets.txt")
        print("  python3 packet_analyzer.py --examples --quick")
        print("  python3 packet_analyzer.py --hex 'abc123...' --export output.txt")

if __name__ == "__main__":
    main()