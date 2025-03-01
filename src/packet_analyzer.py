import pyshark
import pandas as pd
import os

class PacketAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file

    def extract_features(self):
        """
        Reads a PCAP/PCAPNG file using PyShark and extracts packet features including TCP & TLS headers.
        """
        try:
            logging.info(f"📂 Opening PCAP file: {self.pcap_file}")
            cap = pyshark.FileCapture(self.pcap_file, keep_packets=False)
            packets = []

            print("🔍 Processing packets...")
            for pkt in cap:
                try:
                    packet_data = {}

                    # Extract basic packet information
                    try:
                        packet_data['packet_size'] = int(pkt.length)
                    except Exception as e:
                        print(f"⚠ Error extracting packet_size: {e}")
                        packet_data['packet_size'] = None

                    try:
                        packet_data['timestamp'] = float(pkt.sniff_timestamp)
                    except Exception as e:
                        print(f"⚠ Error extracting timestamp: {e}")
                        packet_data['timestamp'] = None

                    try:
                        packet_data['protocol'] = pkt.highest_layer
                    except Exception as e:
                        print(f"⚠ Error extracting protocol: {e}")
                        packet_data['protocol'] = None

                    # Extract IP fields
                    try:
                        packet_data['ip_src'] = pkt.ip.src if hasattr(pkt, 'ip') else None
                        packet_data['ip_dst'] = pkt.ip.dst if hasattr(pkt, 'ip') else None
                    except Exception as e:
                        print(f"⚠ Error extracting IP fields: {e}")
                        packet_data['ip_src'] = None
                        packet_data['ip_dst'] = None

                    # Extract transport layer protocol
                    try:
                        packet_data['transport'] = pkt.transport_layer if hasattr(pkt, 'transport_layer') else None
                    except Exception as e:
                        print(f"⚠ Error extracting transport: {e}")
                        packet_data['transport'] = None

                    # Extract TLS version
                    try:
                        packet_data['tls_version'] = pkt.tls.record_version if hasattr(pkt, 'tls') else None
                    except Exception as e:
                        print(f"⚠ Error extracting tls_version: {e}")
                        packet_data['tls_version'] = None

                    # Extract TCP fields
                    if hasattr(pkt, 'tcp'):
                        try:
                            packet_data.update({
                                'tcp_seq': int(pkt.tcp.seq) if pkt.tcp.seq.isnumeric() else None,
                                'tcp_ack': int(pkt.tcp.ack) if pkt.tcp.ack.isnumeric() else None,
                                'tcp_window': int(pkt.tcp.window_size) if pkt.tcp.window_size.isnumeric() else None,
                                'tcp_flags': int(pkt.tcp.flags, 16) if hasattr(pkt.tcp, 'flags') else None
                            })
                        except Exception as e:
                            print(f"⚠ Error extracting TCP fields: {e}")
                            packet_data.update({
                                'tcp_seq': None,
                                'tcp_ack': None,
                                'tcp_window': None,
                                'tcp_flags': None
                            })

                    # Extract TLS fields
                    if hasattr(pkt, 'tls'):
                        try:
                            packet_data.update({
                                'tls_handshake_type': int(pkt.tls.handshake_type) if hasattr(pkt.tls, 'handshake_type') else None,
                                'tls_cipher_suite': pkt.tls.cipher_suite if hasattr(pkt.tls, 'cipher_suite') else None
                            })
                        except Exception as e:
                            print(f"⚠ Error extracting TLS fields: {e}")
                            packet_data.update({
                                'tls_handshake_type': None,
                                'tls_cipher_suite': None
                            })


                    packets.append(packet_data)

                except Exception as e:
                    print(f"⚠ Error processing packet: {e}")
                    continue

            cap.close()
            print("🔚 Closing the PCAP file.")

            # Convert list of packet data to DataFrame
            df = pd.DataFrame(packets)
            print("📊 Converting packet data to DataFrame.")

            # Convert numeric columns
            # Ensure numeric columns are correctly converted
            # Convert numeric columns properly
            numeric_columns = ['packet_size', 'tcp_seq', 'tcp_ack', 'tcp_window', 'tcp_flags', 'tls_handshake_type']
            for col in numeric_columns:
                if col in df.columns:
                    df[col] = pd.to_numeric(df[col], errors='coerce')

            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_numeric(df['timestamp'], errors='coerce')

            # Ensure categorical columns are always strings
            categorical_columns = ['protocol', 'ip_src', 'ip_dst', 'transport', 'tls_version', 'tls_cipher_suite']
            for col in categorical_columns:
                if col in df.columns:
                    df[col] = df[col].astype(str).replace({'nan': 'Unknown', 'None': 'Unknown'})

            # Ensure TLS fields are always string values
            if 'tls_version' in df.columns:
                df['tls_version'] = df['tls_version'].astype(str).replace({'nan': 'Unknown', 'None': 'Unknown'})

            if 'tls_cipher_suite' in df.columns:
                df['tls_cipher_suite'] = df['tls_cipher_suite'].astype(str).replace(
                    {'nan': 'Unknown', 'None': 'Unknown'})

            # Debug print to verify final column values
            print("✅ Final DataFrame preview before plotting:")
            print(df.head())

            return df

        except Exception as e:
            print(f"❌ Error reading file {self.pcap_file}: {e}")
            return pd.DataFrame()
