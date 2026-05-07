import datetime
from classify import classify_behavior

def generate_fingerprint(url, features):
    if not features or features["total_packets"] == 0:
        return {
            "site_url": url,
            "error": "No traffic captured"
        }

    total_packets = features["total_packets"]

    # Normalize protocol distribution
    protocol_distribution = {}
    for proto in features["protocols"]:
        protocol_distribution[proto] = (
            (features["protocols"][proto] / total_packets) * 100
            if total_packets > 0 else 0
        )

    # Determine top protocol
    top_protocol = max(protocol_distribution, key=protocol_distribution.get)

    # Classification
    label, confidence = classify_behavior(features)

    return {
        "site_url": url,
        "capture_timestamp": str(datetime.datetime.now()),
        "total_packets": total_packets,
        "total_bytes": features["total_bytes"],
        "top_protocol": top_protocol,
        "unique_ips": features["unique_ips"],
        "dns_queries": features["dns_queries"],
        "mean_packet_size": features["mean_size"],
        "max_packet_size": features["max_size"],
        "protocol_distribution": protocol_distribution,
        "timeline": features["timeline"],
        "sizes": features["sizes"],
        "behavior_label": label,
        "confidence": confidence
    }