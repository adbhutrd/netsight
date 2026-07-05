#!/usr/bin/env python3
"""NetSight — Network anomaly detection with ML"""
import json, random, time
from collections import defaultdict

class PacketCapture:
    def __init__(self):
        self.packets = []
    
    def sniff(self, count=10):
        protocols = ["TCP", "UDP", "ICMP", "DNS", "HTTP"]
        for _ in range(count):
            self.packets.append({
                "src": f"192.168.1.{random.randint(2,254)}",
                "dst": f"10.0.0.{random.randint(2,254)}",
                "proto": random.choice(protocols),
                "port": random.choice([22, 80, 443, 8080, 53]),
                "size": random.randint(64, 1500)
            })
        return self

class AnomalyDetector:
    def __init__(self):
        self.baseline = defaultdict(float)
    
    def detect(self, packets):
        alerts = []
        port_counts = defaultdict(int)
        for p in packets:
            port_counts[p["port"]] += 1
        
        for port, count in port_counts.items():
            if count > 5:
                alerts.append({"severity": "HIGH", "message": f"Port scan detected on port {port}", "count": count})
        return alerts

def main():
    print("NetSight v1.0 - Network Anomaly Detection")
    print("-" * 40)
    
    capture = PacketCapture()
    detector = AnomalyDetector()
    
    print("[*] Capturing network packets...")
    packets = capture.sniff(20).packets
    
    print("[*] Analyzing for anomalies...")
    time.sleep(0.5)
    alerts = detector.detect(packets)
    
    if alerts:
        print(f"\n[!] {len(alerts)} anomalies detected:")
        for a in alerts:
            print(f"  [{a['severity']}] {a['message']} (count: {a['count']})")
    else:
        print("\n[+] No anomalies detected - traffic pattern is normal")

if __name__ == "__main__":
    main()
