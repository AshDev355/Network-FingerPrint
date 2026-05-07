from scapy.all import rdpcap, TCP, UDP, DNS, ICMP, IP
import statistics
from collections import defaultdict

def extract_features(pcap_file):
    """Extract features from pcap file"""
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error reading pcap file: {e}")
        return None
    
    if not packets:
        return None
    
    total_packets = len(packets)
    sizes = []
    protocols = {"TCP": 0, "UDP": 0, "DNS": 0, "ICMP": 0, "HTTPS": 0, "OTHER": 0}
    ips = set()
    dns_queries = []
    total_bytes = 0
    timeline = defaultdict(int)
    inter_arrival_times = []
    
    start_time = float(packets[0].time) if packets else 0
    previous_time = start_time
    
    for pkt in packets:
        size = len(pkt)
        sizes.append(size)
        total_bytes += size
        
        # Timeline (bytes per second)
        current_time = float(pkt.time)
        second = int(current_time - start_time)
        timeline[second] += size
        
        # Inter-arrival time
        inter_arrival = current_time - previous_time
        if inter_arrival > 0:
            inter_arrival_times.append(inter_arrival)
        previous_time = current_time
        
        # Protocol detection
        if pkt.haslayer(TCP):
            protocols["TCP"] += 1
            # Check for HTTPS (port 443)
            if pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                protocols["HTTPS"] += 1
        elif pkt.haslayer(UDP):
            protocols["UDP"] += 1
        elif pkt.haslayer(DNS):
            protocols["DNS"] += 1
            try:
                if hasattr(pkt[DNS], 'qd') and pkt[DNS].qd:
                    qname = pkt[DNS].qd.qname.decode('utf-8', errors='ignore')
                    if qname not in dns_queries:
                        dns_queries.append(qname)
            except Exception:
                pass
        elif pkt.haslayer(ICMP):
            protocols["ICMP"] += 1
        else:
            protocols["OTHER"] += 1
        
        # Collect destination IPs
        if pkt.haslayer(IP):
            ips.add(pkt[IP].dst)
    
    # Calculate statistics
    mean_size = statistics.mean(sizes) if sizes else 0
    max_size = max(sizes) if sizes else 0
    min_size = min(sizes) if sizes else 0
    
    mean_inter_arrival = statistics.mean(inter_arrival_times) if inter_arrival_times else 0
    
    return {
        "total_packets": total_packets,
        "protocols": protocols,
        "sizes": sizes,
        "mean_size": round(mean_size, 2),
        "max_size": max_size,
        "min_size": min_size,
        "unique_ips": list(ips),
        "dns_queries": dns_queries,
        "total_bytes": total_bytes,
        "timeline": dict(timeline),
        "inter_arrival_times": inter_arrival_times,
        "mean_inter_arrival": round(mean_inter_arrival, 6)
    }

if __name__ == "__main__":
    # Test extraction
    import sys
    if len(sys.argv) > 1:
        features = extract_features(sys.argv[1])
        if features:
            print(f"Extracted features from {features['total_packets']} packets")
            print(f"Protocols: {features['protocols']}")
    else:
        print("Usage: python extract.py <pcap_file>")