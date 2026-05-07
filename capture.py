from scapy.all import sniff, wrpcap, IP
import requests
import threading
import socket
import os

def resolve_ip(url):
    """Resolve domain name to IP address"""
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def generate_traffic(url):
    """Make HTTP request to generate network traffic"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, timeout=10, headers=headers, allow_redirects=True)
        print(f"Traffic generated: {url} - Status: {response.status_code}")
    except Exception as e:
        print(f"Traffic generation warning: {e}")

def capture_packets(url, output_file="temp/capture.pcap", duration=10):
    """Capture packets for a specific URL"""
    target_ip = resolve_ip(url)
    
    if not target_ip:
        print(f"Could not resolve IP for {url}")
        return None
    
    print(f"📡 Capturing traffic for {url} ({target_ip})")
    
    packets = []
    sniffing_complete = threading.Event()
    
    def packet_filter(pkt):
        """Filter packets related to target IP"""
        if pkt.haslayer(IP):
            return pkt[IP].src == target_ip or pkt[IP].dst == target_ip
        return False
    
    def sniff_thread():
        """Sniff packets in separate thread"""
        nonlocal packets
        try:
            packets = sniff(
                timeout=duration,
                lfilter=packet_filter,
                store=True
            )
            sniffing_complete.set()
        except Exception as e:
            print(f"Sniffing error: {e}")
            sniffing_complete.set()
    
    # Start sniffing in background thread
    sniffer = threading.Thread(target=sniff_thread)
    sniffer.daemon = True
    sniffer.start()
    
    # Wait briefly then generate traffic
    import time
    time.sleep(0.5)
    
    # Generate traffic (this runs in main thread)
    generate_traffic(url)
    
    # Wait for sniffing to complete
    sniffing_complete.wait(timeout=duration + 5)
    
    if packets:
        # Save to pcap file
        os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
        wrpcap(output_file, packets)
        print(f"✅ Captured {len(packets)} packets for {url}")
        return output_file
    else:
        print(f"⚠️ No packets captured for {url}")
        return None

if __name__ == "__main__":
    # Test capture
    result = capture_packets("https://example.com", duration=10)
    if result:
        print(f"Capture saved to: {result}")