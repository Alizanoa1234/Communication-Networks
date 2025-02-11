import pyshark
import os
import sys
import pyshark
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns


class PacketAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file

    def extract_features(self):
        # Attempt to read the PCAP file, handle exceptions gracefully
        try:
            cap = pyshark.FileCapture(self.pcap_file, keep_packets=False)
        except Exception as e:
            print(f"Error reading PCAP file: {e}")
            return pd.DataFrame()

        packets = []
        last_time = None

        for pkt in cap:
            try:
                packet_size = int(pkt.length)
                timestamp = float(pkt.sniff_timestamp)
                inter_arrival_time = (timestamp - last_time) if last_time else 0
                last_time = timestamp

                # Extract IP and transport layer details
                ip_src = pkt.ip.src if hasattr(pkt, 'ip') else '0.0.0.0'
                ip_dst = pkt.ip.dst if hasattr(pkt, 'ip') else '0.0.0.0'
                src_port = pkt[pkt.transport_layer].srcport if hasattr(pkt, 'transport_layer') else 0
                dst_port = pkt[pkt.transport_layer].dstport if hasattr(pkt, 'transport_layer') else 0
                tls_version = pkt.tls.record_version if 'TLS' in pkt else 'Unknown'

                packets.append({
                    'packet_size': packet_size,
                    'inter_arrival_time': inter_arrival_time,
                    'ip_src': ip_src,
                    'ip_dst': ip_dst,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'tls_version': tls_version
                })
            except Exception:
                continue

        cap.close()
        df = pd.DataFrame(packets)
        if df.empty:
            print(f"No valid packets found in {self.pcap_file}. Check the PCAP file.")
        return df