def classify_behavior(data):
    avg_size = data["mean_size"]
    total_bytes = data["total_bytes"]
    ip_count = len(data["unique_ips"])
    total_packets = data["total_packets"]

    https_ratio = data["protocols"]["HTTPS"] / total_packets if total_packets else 0

    if total_bytes > 700000 and avg_size > 900:
        return "Streaming", 0.92
    elif ip_count > 15 and total_packets > 200:
        return "Social Media", 0.85
    elif total_packets < 60 and len(data["dns_queries"]) < 3:
        return "Static Content", 0.80
    elif avg_size < 250 and https_ratio > 0.7:
        return "API-Heavy", 0.83
    else:
        return "Unknown", 0.50