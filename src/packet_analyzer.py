import pyshark
import pandas as pd
import os
import logging
from pathlib import Path
from collections import defaultdict
from data_processor import DataProcessor

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Define data directories
BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
RESULTS_DIR = BASE_DIR / "res"
CSV_DIR = RESULTS_DIR / "CSV_files"
GRAPH_DIR = RESULTS_DIR / "Graphs"

# Ensure necessary directories exist
os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(CSV_DIR, exist_ok=True)
os.makedirs(GRAPH_DIR, exist_ok=True)


class PacketAnalyzer:
	def __init__(self, pcap_file):
		self.pcap_file = pcap_file
		self.flows = defaultdict(lambda: {'size': 0, 'volume': 0, 'last_timestamp': None})

	def extract_features(self):
		"""
        Reads a PCAP file using PyShark and extracts packet features,
        including Flow-Level and Traffic-Level features.

        Returns:
            pd.DataFrame: Dataframe containing extracted traffic data.
        """
		try:
			# Open the pcap file with PyShark (no packet buffering for faster parsing)
			cap = pyshark.FileCapture(self.pcap_file, keep_packets=False)

			packets = []

			for pkt in cap:
				try:
					# Ensure packet has IP and Transport Layer
					if not hasattr(pkt, 'ip') or not hasattr(pkt, 'transport_layer'):
						continue  # Skip packets without these layers

					# Identify flow key (5-tuple: src IP, dst IP, protocol, src port, dst port)
					flow_key = (
						pkt.ip.src,
						pkt.ip.dst,
						pkt.transport_layer,
						pkt[pkt.transport_layer].srcport if hasattr(pkt, pkt.transport_layer) else None,
						pkt[pkt.transport_layer].dstport if hasattr(pkt, pkt.transport_layer) else None,
					)

					# Extract basic packet features
					packet_data = {
						'timestamp': float(pkt.sniff_timestamp),
						'packet_size': int(pkt.length),
						'protocol': pkt.highest_layer,
						'ip_src': pkt.ip.src,
						'ip_dst': pkt.ip.dst,
						'transport': pkt.transport_layer
					}

					# TCP-specific features
					if hasattr(pkt, 'tcp'):
						packet_data.update({
							'tcp_seq': int(pkt.tcp.seq) if hasattr(pkt.tcp,
																   'seq') and pkt.tcp.seq.isnumeric() else None,
							'tcp_ack': int(pkt.tcp.ack) if hasattr(pkt.tcp,
																   'ack') and pkt.tcp.ack.isnumeric() else None,
							'tcp_window': int(pkt.tcp.window_size) if hasattr(pkt.tcp,
																			  'window_size') and pkt.tcp.window_size.isnumeric() else None,
							'tcp_flags': int(pkt.tcp.flags, 16) if hasattr(pkt.tcp, 'flags') else None,
						})

					# TLS-specific features
					if hasattr(pkt, 'tls'):
						packet_data.update({
							'tls_handshake_type': int(pkt.tls.handshake_type) if hasattr(pkt.tls,
																						 'handshake_type') else None,
							'tls_version': pkt.tls.record_version if hasattr(pkt.tls, 'record_version') else None,
							'tls_cipher_suite': pkt.tls.cipher_suite if hasattr(pkt.tls, 'cipher_suite') else None
						})

					# Flow-level metrics
					self.flows[flow_key]['size'] += packet_data['packet_size']
					self.flows[flow_key]['volume'] += 1
					packet_data['flow_size'] = self.flows[flow_key]['size']
					packet_data['flow_volume'] = self.flows[flow_key]['volume']

					# Calculate Inter-Packet Time
					if self.flows[flow_key]['last_timestamp'] is not None:
						packet_data['inter_packet_time'] = packet_data['timestamp'] - self.flows[flow_key][
							'last_timestamp']
					else:
						packet_data['inter_packet_time'] = None
					self.flows[flow_key]['last_timestamp'] = packet_data['timestamp']

					# Append extracted packet data
					packets.append(packet_data)

				except Exception as e:
					logging.warning(f"⚠ Error processing packet: {e}")
					continue  # Skip the problematic packet

			cap.close()
			df = pd.DataFrame(packets)

			# Clean the dataframe using DataProcessor
			df = DataProcessor.clean_dataframe(df)

			# Save to CSV
			output_csv = Path(self.pcap_file).with_suffix('.csv')
			DataProcessor.save_dataframe_to_csv(df, output_csv)

			return df

		except Exception as e:
			logging.error(f"❌ Error reading file {self.pcap_file}: {e}")
			return pd.DataFrame()  # Return empty DataFrame if error occurs