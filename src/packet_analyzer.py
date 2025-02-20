import pyshark
import pandas as pd

class PacketAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file

    def extract_features(self):
        """
        Reads a PCAP/PCAPNG file using PyShark and extracts packet features.
        Returns a Pandas DataFrame containing parsed data.
        """
        try:
            cap = pyshark.FileCapture(self.pcap_file, keep_packets=False)

            packets = []
            for pkt in cap:
                try:
                    packet_size = int(pkt.length)
                    timestamp = float(pkt.sniff_timestamp)
                    protocol = pkt.highest_layer
                    ip_src = pkt.ip.src if hasattr(pkt, 'ip') else None
                    ip_dst = pkt.ip.dst if hasattr(pkt, 'ip') else None
                    transport = pkt.transport_layer if hasattr(pkt, 'transport_layer') else None
                    tls_version = pkt.tls.record_version if 'TLS' in pkt else None

                    packets.append({
                        'packet_size': packet_size,
                        'timestamp': timestamp,
                        'protocol': protocol,
                        'ip_src': ip_src,
                        'ip_dst': ip_dst,
                        'transport': transport,
                        'tls_version': tls_version
                    })
                except Exception:
                    continue  # Skip problematic packets

            cap.close()
            return pd.DataFrame(packets)

        except Exception as e:
            print(f"❌ Error reading file {self.pcap_file}: {e}")
            return pd.DataFrame()
