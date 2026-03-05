#!/usr/bin/env python3
"""
Live packet capture and feature extraction module for SmartIDS
Extracts flow-based features from live network traffic using pyshark
"""
try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False
    pyshark = None

import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Tuple
import queue

class FlowTracker:
    """Tracks network flows and extracts features similar to CICIDS2017 format"""
    
    def __init__(self, timeout=120):
        """
        Initialize flow tracker
        
        Args:
            timeout: Flow timeout in seconds (flows older than this are removed)
        """
        self.timeout = timeout
        self.flows: Dict[str, Dict] = {}
        self.flow_lock = threading.Lock()
        self.last_cleanup = time.time()
        self.cleanup_interval = 30  # Clean up old flows every 30 seconds
        
    def _get_flow_key(self, src_ip: str, dst_ip: str, src_port: str, dst_port: str, protocol: str) -> str:
        """Generate a unique flow key"""
        # Use canonical form (smaller IP first)
        if src_ip < dst_ip:
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
    
    def _cleanup_old_flows(self):
        """Remove flows that haven't been updated recently"""
        current_time = time.time()
        if current_time - self.last_cleanup < self.cleanup_interval:
            return
        
        with self.flow_lock:
            expired_flows = []
            for flow_key, flow_data in self.flows.items():
                if current_time - flow_data['last_seen'] > self.timeout:
                    expired_flows.append(flow_key)
            
            for key in expired_flows:
                del self.flows[key]
        
        self.last_cleanup = current_time
    
    def update_flow(self, packet_info: Dict) -> Optional[Dict]:
        """
        Update flow with new packet and return features if flow is complete
        
        Args:
            packet_info: Dictionary with packet information
            
        Returns:
            Feature dictionary if flow should be analyzed, None otherwise
        """
        self._cleanup_old_flows()
        
        src_ip = packet_info.get('src_ip', '')
        dst_ip = packet_info.get('dst_ip', '')
        src_port = str(packet_info.get('src_port', 0))
        dst_port = str(packet_info.get('dst_port', 0))
        protocol = packet_info.get('protocol', 'TCP')
        
        if not src_ip or not dst_ip:
            return None
        
        flow_key = self._get_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)
        packet_size = packet_info.get('packet_size', 0)
        timestamp = packet_info.get('timestamp', time.time())
        direction = packet_info.get('direction', 'forward')  # forward or backward
        
        with self.flow_lock:
            if flow_key not in self.flows:
                # Initialize new flow
                self.flows[flow_key] = {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'start_time': timestamp,
                    'last_seen': timestamp,
                    'fwd_packets': [],
                    'bwd_packets': [],
                    'fwd_sizes': [],
                    'bwd_sizes': [],
                    'fwd_times': [],
                    'bwd_times': [],
                    'iat_times': [],
                    'last_packet_time': timestamp,
                    'packet_count': 0
                }
            
            flow = self.flows[flow_key]
            flow['last_seen'] = timestamp
            flow['packet_count'] += 1
            
            # Determine direction (simplified: use source IP to determine direction)
            # In a real scenario, you'd track which side initiated the connection
            if direction == 'forward' or len(flow['fwd_packets']) <= len(flow['bwd_packets']):
                flow['fwd_packets'].append(timestamp)
                flow['fwd_sizes'].append(packet_size)
                flow['fwd_times'].append(timestamp)
            else:
                flow['bwd_packets'].append(timestamp)
                flow['bwd_sizes'].append(packet_size)
                flow['bwd_times'].append(timestamp)
            
            # Calculate IAT (Inter-Arrival Time)
            if flow['packet_count'] > 1:
                iat = timestamp - flow['last_packet_time']
                if iat > 0:
                    flow['iat_times'].append(iat)
            flow['last_packet_time'] = timestamp
            
            # Extract features if we have enough packets or flow is old enough
            # For live capture, be more lenient - allow flows with 2+ packets after 0.5 seconds
            min_packets = 2
            flow_age = timestamp - flow['start_time']
            min_age = 0.5  # Reduced from 1.0 second for faster response
            
            if flow['packet_count'] >= min_packets and flow_age >= min_age:
                features = self._extract_features(flow_key, flow)
                # Don't remove flow yet, keep it for more packets
                return features
        
        return None
    
    def _extract_features(self, flow_key: str, flow: Dict) -> Dict:
        """Extract CICIDS2017-like features from flow"""
        fwd_sizes = flow['fwd_sizes'] if flow['fwd_sizes'] else [0]
        bwd_sizes = flow['bwd_sizes'] if flow['bwd_sizes'] else [0]
        fwd_times = flow['fwd_times'] if flow['fwd_times'] else []
        bwd_times = flow['bwd_times'] if flow['bwd_times'] else []
        iat_times = flow['iat_times'] if flow['iat_times'] else [0]
        
        flow_duration = flow['last_seen'] - flow['start_time']
        total_fwd_packets = len(flow['fwd_packets'])
        total_bwd_packets = len(flow['bwd_packets'])
        total_fwd_length = sum(fwd_sizes)
        total_bwd_length = sum(bwd_sizes)
        
        # Forward packet statistics
        fwd_max = max(fwd_sizes) if fwd_sizes else 0
        fwd_min = min(fwd_sizes) if fwd_sizes else 0
        fwd_mean = np.mean(fwd_sizes) if fwd_sizes else 0
        fwd_std = np.std(fwd_sizes) if fwd_sizes else 0
        
        # Backward packet statistics
        bwd_max = max(bwd_sizes) if bwd_sizes else 0
        bwd_min = min(bwd_sizes) if bwd_sizes else 0
        bwd_mean = np.mean(bwd_sizes) if bwd_sizes else 0
        bwd_std = np.std(bwd_sizes) if bwd_sizes else 0
        
        # Flow statistics
        flow_bytes_per_sec = (total_fwd_length + total_bwd_length) / flow_duration if flow_duration > 0 else 0
        flow_packets_per_sec = (total_fwd_packets + total_bwd_packets) / flow_duration if flow_duration > 0 else 0
        
        # IAT statistics
        iat_mean = np.mean(iat_times) if iat_times else 0
        iat_std = np.std(iat_times) if iat_times else 0
        iat_max = max(iat_times) if iat_times else 0
        iat_min = min(iat_times) if iat_times else 0
        
        # Additional features (simplified - real CICIDS2017 has more)
        # We'll pad with zeros for missing features
        features = {
            'Destination Port': int(flow['dst_port']) if flow['dst_port'].isdigit() else 0,
            'Flow Duration': flow_duration * 1000000,  # Convert to microseconds
            'Total Fwd Packets': total_fwd_packets,
            'Total Backward Packets': total_bwd_packets,
            'Total Length of Fwd Packets': total_fwd_length,
            'Total Length of Bwd Packets': total_bwd_length,
            'Fwd Packet Length Max': fwd_max,
            'Fwd Packet Length Min': fwd_min,
            'Fwd Packet Length Mean': fwd_mean,
            'Fwd Packet Length Std': fwd_std,
            'Bwd Packet Length Max': bwd_max,
            'Bwd Packet Length Min': bwd_min,
            'Bwd Packet Length Mean': bwd_mean,
            'Bwd Packet Length Std': bwd_std,
            'Flow Bytes/s': flow_bytes_per_sec,
            'Flow Packets/s': flow_packets_per_sec,
            'Flow IAT Mean': iat_mean * 1000000,  # Convert to microseconds
            'Flow IAT Std': iat_std * 1000000,
            'Flow IAT Max': iat_max * 1000000,
            'Flow IAT Min': iat_min * 1000000,
            'flow_key': flow_key,
            'timestamp': flow['last_seen']
        }
        
        return features


class LivePacketCapture:
    """Live packet capture using pyshark"""
    
    def __init__(self, interface: str = None, feature_names: List[str] = None):
        """
        Initialize live packet capture
        
        Args:
            interface: Network interface name (None for default)
            feature_names: List of expected feature names from trained model
        """
        self.interface = interface
        self.feature_names = feature_names or []
        self.flow_tracker = FlowTracker()
        self.capture = None
        self.capturing = False
        self.capture_thread = None
        self.packet_queue = queue.Queue()
        self.feature_queue = queue.Queue()
        # Statistics
        self.total_packets_captured = 0
        self.packets_with_ip = 0
        self.packets_processed = 0
        self.flows_created = 0
        self.stats_lock = threading.Lock()
        
    def _extract_packet_info(self, packet) -> Optional[Dict]:
        """Extract relevant information from pyshark packet"""
        try:
            # Convert timestamp to float (pyshark returns float, but ensure it's a number)
            timestamp = float(packet.sniff_timestamp) if hasattr(packet, 'sniff_timestamp') else time.time()
            
            packet_info = {
                'timestamp': timestamp,
                'packet_size': int(packet.length) if hasattr(packet, 'length') else 0,
                'protocol': packet.transport_layer if hasattr(packet, 'transport_layer') else 'UNKNOWN',
                'direction': 'forward'  # Simplified
            }
            
            # Extract IP layer info
            if hasattr(packet, 'ip'):
                packet_info['src_ip'] = packet.ip.src
                packet_info['dst_ip'] = packet.ip.dst
            elif hasattr(packet, 'ipv6'):
                packet_info['src_ip'] = packet.ipv6.src
                packet_info['dst_ip'] = packet.ipv6.dst
            else:
                return None
            
            # Extract port info
            if hasattr(packet, 'tcp'):
                packet_info['src_port'] = packet.tcp.srcport
                packet_info['dst_port'] = packet.tcp.dstport
            elif hasattr(packet, 'udp'):
                packet_info['src_port'] = packet.udp.srcport
                packet_info['dst_port'] = packet.udp.dstport
            else:
                packet_info['src_port'] = 0
                packet_info['dst_port'] = 0
            
            return packet_info
        except Exception as e:
            print(f"Error extracting packet info: {e}")
            return None
    
    def _packet_handler(self, packet):
        """Handle captured packet"""
        if not self.capturing:
            return
        
        try:
            with self.stats_lock:
                self.total_packets_captured += 1
                # Log first packet and every 100 packets for debugging
                if self.total_packets_captured == 1:
                    print(f"✓ FIRST PACKET CAPTURED! Total: {self.total_packets_captured}")
                elif self.total_packets_captured % 100 == 0:
                    print(f"Captured {self.total_packets_captured} packets so far...")
            
            packet_info = self._extract_packet_info(packet)
            if packet_info:
                with self.stats_lock:
                    self.packets_with_ip += 1
                    self.packets_processed += 1
                
                self.packet_queue.put(packet_info)
                
                # Update flow and get features
                features = self.flow_tracker.update_flow(packet_info)
                if features:
                    with self.stats_lock:
                        self.flows_created += 1
                    self.feature_queue.put(features)
                    print(f"Flow created! Total flows: {self.flows_created}")
        except Exception as e:
            print(f"Error in packet handler: {e}")
            import traceback
            traceback.print_exc()
    
    def _capture_thread_func(self):
        """Thread function for packet capture"""
        if not PYSHARK_AVAILABLE:
            print("Error: pyshark is not installed. Please install it with: pip install pyshark")
            self.capturing = False
            return
        
        try:
            if self.interface:
                # Validate that interface is not loopback
                if self.interface.lower().startswith('lo') or 'loopback' in self.interface.lower():
                    print(f"Warning: {self.interface} is a loopback interface. Finding WiFi interface instead...")
                    self.interface = None  # Force re-detection
            else:
                # Try to find a suitable interface (prefer WiFi)
                wifi_interface = None
                all_interfaces = []
                
                # First, try to find WiFi interface on macOS
                try:
                    import platform
                    if platform.system() == 'Darwin':  # macOS
                        import subprocess
                        result = subprocess.run(['networksetup', '-listallhardwareports'], 
                                              capture_output=True, text=True, timeout=2)
                        if result.returncode == 0:
                            lines = result.stdout.split('\n')
                            for i, line in enumerate(lines):
                                if 'Wi-Fi' in line or 'AirPort' in line:
                                    if i + 1 < len(lines):
                                        device_line = lines[i + 1]
                                        if 'Device:' in device_line:
                                            wifi_interface = device_line.split('Device:')[1].strip()
                                            break
                except Exception:
                    pass
                
                # Get list of all interfaces
                try:
                    import psutil
                    interfaces = list(psutil.net_if_addrs().keys())
                    all_interfaces = interfaces
                except ImportError:
                    # psutil not available, try alternative method
                    try:
                        import subprocess
                        import platform
                        if platform.system() == 'Darwin':
                            result = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=2)
                            if result.returncode == 0:
                                import re
                                all_interfaces = re.findall(r'^([a-z]+\d+):', result.stdout, re.MULTILINE)
                    except Exception:
                        pass
                except Exception:
                    pass
                
                # Filter out loopback interfaces
                loopback_keywords = ['lo', 'loopback', 'Loopback']
                valid_interfaces = [iface for iface in all_interfaces 
                                  if not any(keyword in iface.lower() for keyword in loopback_keywords)]
                
                # Prioritize WiFi interface
                if wifi_interface:
                    if wifi_interface in valid_interfaces:
                        self.interface = wifi_interface
                        print(f"Auto-selected WiFi interface: {wifi_interface}")
                    elif wifi_interface not in all_interfaces:
                        # WiFi interface from networksetup might not be in psutil list, try it anyway
                        self.interface = wifi_interface
                        print(f"Auto-selected WiFi interface: {wifi_interface} (from system)")
                
                # If no WiFi found, use first valid non-loopback interface
                if not self.interface and valid_interfaces:
                    self.interface = valid_interfaces[0]
                    print(f"Auto-selected interface: {self.interface}")
                
                # Last resort: try common interface names (prioritize en0 for macOS WiFi)
                if not self.interface:
                    import platform
                    if platform.system() == 'Darwin':
                        common_interfaces = ['en0', 'en1', 'en2']  # macOS: en0 is usually WiFi
                    else:
                        common_interfaces = ['eth0', 'wlan0', 'wlan1', 'en0', 'en1']
                    
                    for iface in common_interfaces:
                        # Check if it's not loopback
                        if not any(keyword in iface.lower() for keyword in ['lo', 'loopback']):
                            self.interface = iface
                            print(f"Trying common interface: {self.interface}")
                            break
                
                if not self.interface:
                    raise Exception("Could not find a suitable network interface. Please specify one manually (e.g., 'en0' for WiFi on macOS).")
            
            # Create capture - try with IP filter first, fallback to no filter
            try:
                display_filter = 'ip'  # Only capture IP packets
                self.capture = pyshark.LiveCapture(
                    interface=self.interface,
                    display_filter=display_filter
                )
                print(f"Created capture with IP filter on {self.interface}")
            except Exception as e:
                print(f"Warning: Could not create capture with filter: {e}")
                print("Trying without filter...")
                self.capture = pyshark.LiveCapture(interface=self.interface)
                print(f"Created capture without filter on {self.interface}")
            print(f"Starting packet capture on interface: {self.interface}")
            print("Waiting for packets... (make sure you have network traffic)")
            print("Tip: Try browsing websites or running 'ping google.com' in another terminal")
            print("\nNOTE: On macOS, packet capture may require special permissions.")
            print("If no packets are captured, you may need to:")
            print("  1. Grant Terminal/IDE network access in System Preferences")
            print("  2. Or run with: sudo python app.py (not recommended)")
            print()
            
            # Try different capture methods - pyshark API can vary
            try:
                print("Entering capture loop (waiting for packets)...")
                
                # Method 1: Try sniff_continuously if available
                try:
                    for packet in self.capture.sniff_continuously():
                        if not self.capturing:
                            print("Capture stopped by flag")
                            break
                        self._packet_handler(packet)
                except AttributeError:
                    # Method 2: Use apply_on_packets with proper callback
                    print("Using apply_on_packets method...")
                    def packet_callback(pkt):
                        if not self.capturing:
                            return True  # Stop
                        self._packet_handler(pkt)
                        return False  # Continue
                    
                    self.capture.apply_on_packets(packet_callback, packet_count=None)
                except Exception as iter_e:
                    # Method 3: Try direct iteration
                    print(f"Trying direct iteration (sniff_continuously failed: {iter_e})...")
                    for packet in self.capture:
                        if not self.capturing:
                            break
                        self._packet_handler(packet)
            except KeyboardInterrupt:
                print("Capture interrupted")
                self.capturing = False
            except Exception as e:
                print(f"Error during packet capture: {e}")
                import traceback
                traceback.print_exc()
                self.capturing = False
        except Exception as e:
            print(f"Error in capture thread: {e}")
            import traceback
            traceback.print_exc()
            self.capturing = False
    
    def start_capture(self):
        """Start live packet capture"""
        if self.capturing:
            return
        
        # Reset statistics
        with self.stats_lock:
            self.total_packets_captured = 0
            self.packets_with_ip = 0
            self.packets_processed = 0
            self.flows_created = 0
        
        self.capturing = True
        self.capture_thread = threading.Thread(target=self._capture_thread_func, daemon=True)
        self.capture_thread.start()
        print("Live packet capture started")
    
    def stop_capture(self):
        """Stop live packet capture"""
        self.capturing = False
        if self.capture:
            try:
                self.capture.close()
            except:
                pass
        print("Live packet capture stopped")
    
    def get_features(self, timeout: float = 1.0) -> Optional[Dict]:
        """
        Get extracted features from captured packets
        
        Args:
            timeout: Timeout in seconds
            
        Returns:
            Feature dictionary or None
        """
        try:
            features = self.feature_queue.get(timeout=timeout)
            return features
        except queue.Empty:
            return None
    
    def get_statistics(self) -> Dict:
        """Get capture statistics"""
        with self.stats_lock:
            return {
                'total_packets_captured': self.total_packets_captured,
                'packets_with_ip': self.packets_with_ip,
                'packets_processed': self.packets_processed,
                'flows_created': self.flows_created,
                'active_flows': len(self.flow_tracker.flows),
                'features_ready': self.feature_queue.qsize()
            }
    
    def format_features_for_model(self, features: Dict) -> Optional[np.ndarray]:
        """
        Format extracted features to match model's expected input
        
        Args:
            features: Feature dictionary from flow tracker
            
        Returns:
            Numpy array of features in correct order
        """
        if not self.feature_names:
            return None
        
        # Remove metadata fields
        feature_dict = {k: v for k, v in features.items() 
                       if k not in ['flow_key', 'timestamp']}
        
        # Create DataFrame with single row
        df = pd.DataFrame([feature_dict])
        
        # Align with expected feature names
        # Fill missing features with 0
        aligned_features = []
        for feat_name in self.feature_names:
            if feat_name in df.columns:
                aligned_features.append(df[feat_name].iloc[0])
            else:
                aligned_features.append(0.0)
        
        # Convert to numpy array
        feature_array = np.array(aligned_features, dtype=float)
        
        # Handle NaN and Inf
        feature_array = np.nan_to_num(feature_array, nan=0.0, posinf=0.0, neginf=0.0)
        
        return feature_array
