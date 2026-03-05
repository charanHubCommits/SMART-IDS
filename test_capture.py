#!/usr/bin/env python3
"""Test script to verify packet capture is working"""
import sys

try:
    import pyshark
    print("pyshark is installed")
except ImportError:
    print("ERROR: pyshark is not installed")
    sys.exit(1)

interface = 'en0'
print(f"Testing packet capture on interface: {interface}")
print("Make sure you have network traffic (browse web, ping, etc.)")

packet_count = [0]  # Use list to allow modification in nested function

def count_packet(pkt):
    packet_count[0] += 1
    print(f"  Packet {packet_count[0]} captured!")
    if packet_count[0] >= 3:
        return True  # Stop after 3 packets

try:
    cap = pyshark.LiveCapture(interface=interface, display_filter='ip')
    print("Capture object created successfully")
    print("Sniffing for packets (will stop after 3 packets or timeout)...")
    
    cap.apply_on_packets(count_packet, packet_count=3)
    cap.close()
    
    if packet_count[0] > 0:
        print(f"\nSUCCESS: Captured {packet_count[0]} packet(s)!")
        print("Packet capture is working correctly.")
    else:
        print("\nWARNING: No packets captured.")
        print("Possible issues:")
        print("  1. No network traffic on interface")
        print("  2. Permission denied (on macOS, you may need to run with sudo)")
        print("  3. Interface name is wrong")
        
except PermissionError:
    print("\nERROR: Permission denied!")
    print("On macOS, you may need to:")
    print("  1. Run with sudo: sudo python3 test_capture.py")
    print("  2. Or grant Terminal/IDE network access in System Preferences")
except Exception as e:
    print(f"\nERROR: {e}")
    import traceback
    traceback.print_exc()
