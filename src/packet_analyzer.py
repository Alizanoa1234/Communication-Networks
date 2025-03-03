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
RESULTS_DIR = BASE_DIR / "results"
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
		Reads a PCAP file using PyShark and extracts packet features, including Flow-Level and Traffic-Level features.
		"""
		try:
			cap = pyshark.FileCapture(self.pcap_file, keep_packets=False)
			packets = []

			for pkt in cap:
				try:
					flow_key = (pkt.ip.src if hasattr(pkt, 'ip') else None,
								pkt.ip.dst if hasattr(pkt, 'ip') else None,
								pkt.transport_layer if hasattr(pkt, 'transport_layer') else None,
								pkt[pkt.transport_layer].srcport if hasattr(pkt, pkt.transport_layer) else None,
								pkt[pkt.transport_layer].dstport if hasattr(pkt, pkt.transport_layer) else None)

					packet_data = {
						'packet_size': int(pkt.length),
						'timestamp': float(pkt.sniff_timestamp),
						'protocol': pkt.highest_layer,
						'ip_src': pkt.ip.src if hasattr(pkt, 'ip') else None,
						'ip_dst': pkt.ip.dst if hasattr(pkt, 'ip') else None,
						'transport': pkt.transport_layer if hasattr(pkt, 'transport_layer') else None,
						'tls_version': pkt.tls.record_version if hasattr(pkt, 'tls') else None,
						'tcp_seq': int(pkt.tcp.seq) if hasattr(pkt, 'tcp') and pkt.tcp.seq.isnumeric() else None,
						'tcp_ack': int(pkt.tcp.ack) if hasattr(pkt, 'tcp') and pkt.tcp.ack.isnumeric() else None,
						'tcp_window': int(pkt.tcp.window_size) if hasattr(pkt,
																		  'tcp') and pkt.tcp.window_size.isnumeric() else None,
						'tcp_flags': int(pkt.tcp.flags, 16) if hasattr(pkt, 'tcp') and hasattr(pkt.tcp,
																							   'flags') else None,
						'tls_handshake_type': int(pkt.tls.handshake_type) if hasattr(pkt, 'tls') and hasattr(pkt.tls,
																											 'handshake_type') else None,
						'tls_cipher_suite': pkt.tls.cipher_suite if hasattr(pkt, 'tls') and hasattr(pkt, 'tls',
																									'cipher_suite') else None
					}

					# Calculate Flow-Level Features
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

					packets.append(packet_data)

				except Exception:
					continue  # Skip problematic packets

			cap.close()
			df = pd.DataFrame(packets)

			# Clean the dataframe using DataProcessor
			df = DataProcessor.clean_dataframe(df)

			# Save to CSV
			output_csv = CSV_DIR / f"{Path(self.pcap_file).stem}_parsed_data.csv"
			DataProcessor.save_dataframe_to_csv(df, output_csv)

			return df

		except Exception as e:
			logging.error(f"❌ Error reading file {self.pcap_file}: {e}")
			return pd.DataFrame()  # Return empty DataFrame if error occurs
