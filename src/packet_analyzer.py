import pyshark
import pandas as pd


class PacketAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file

    def extract_features(self):
        """
        Reads a PCAP/PCAPNG file using PyShark and extracts packet features including TCP & TLS headers.
        """
        try:
            cap = pyshark.FileCapture(self.pcap_file, keep_packets=False)
            packets = []

            for pkt in cap:
                try:
                    packet_data = {
                        'packet_size': int(pkt.length),
                        'timestamp': float(pkt.sniff_timestamp),
                        'protocol': pkt.highest_layer,
                        'ip_src': pkt.ip.src if hasattr(pkt, 'ip') else None,
                        'ip_dst': pkt.ip.dst if hasattr(pkt, 'ip') else None,
                        'transport': pkt.transport_layer if hasattr(pkt, 'transport_layer') else None,
                        'tls_version': pkt.tls.record_version if hasattr(pkt, 'tls') else None
                    }

                    # Extract TCP fields (Convert to numeric values)
                    if hasattr(pkt, 'tcp'):
                        try:
                            packet_data.update({
                                'tcp_seq': int(pkt.tcp.seq) if pkt.tcp.seq.isnumeric() else None,
                                'tcp_ack': int(pkt.tcp.ack) if pkt.tcp.ack.isnumeric() else None,
                                'tcp_window': int(pkt.tcp.window_size) if pkt.tcp.window_size.isnumeric() else None,
                                'tcp_flags': int(pkt.tcp.flags, 16) if pkt.tcp.flags.isnumeric() else None
                                # Convert hex flags to int
                            })
                        except Exception:
                            packet_data.update({
                                'tcp_seq': None,
                                'tcp_ack': None,
                                'tcp_window': None,
                                'tcp_flags': None
                            })

                    # Extract TLS fields
                    if hasattr(pkt, 'tls'):
                        packet_data.update({
                            'tls_handshake_type': int(pkt.tls.handshake_type) if hasattr(pkt.tls,
                                                                                         'handshake_type') else None,
                            'tls_cipher_suite': pkt.tls.cipher_suite if hasattr(pkt.tls, 'cipher_suite') else None
                        })

                    packets.append(packet_data)

                except Exception:
                    continue  # Skip problematic packets

            cap.close()
            return pd.DataFrame(packets)

        except Exception as e:
            print(f"❌ Error reading file {self.pcap_file}: {e}")
            return pd.DataFrame()  # Return empty DataFrame if error occurs
