import pyshark
import pandas as pd
import os
import numpy as np
import entropy
import logging


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
			flows = {}
			previous_timestamp = None
			logging.info("🔍 Processing packets...")

			for pkt in cap:
				try:
					packet_data = {}
					packet_data['packet_size'] = int(pkt.length) if hasattr(pkt, 'length') else None
					packet_data['timestamp'] = float(pkt.sniff_timestamp) if hasattr(pkt, 'sniff_timestamp') else None
					packet_data['protocol'] = pkt.highest_layer if hasattr(pkt, 'highest_layer') else None
					packet_data['ip_src'] = pkt.ip.src if hasattr(pkt, 'ip') else None
					packet_data['ip_dst'] = pkt.ip.dst if hasattr(pkt, 'ip') else None
					packet_data['transport'] = pkt.transport_layer if hasattr(pkt, 'transport_layer') else None
					packet_data['tls_version'] = pkt.tls.record_version if hasattr(pkt, 'tls') else None

					if hasattr(pkt, 'tcp'):
						try:
							packet_data.update({
								'tcp_seq': int(pkt.tcp.seq) if pkt.tcp.seq.isdigit() else None,
								'tcp_ack': int(pkt.tcp.ack) if pkt.tcp.ack.isdigit() else None,
								'tcp_window': int(pkt.tcp.window_size) if pkt.tcp.window_size.isdigit() else None,
								'tcp_flags': int(pkt.tcp.flags, 16) if hasattr(pkt.tcp, 'flags') else None,
								'tcp_srcport': int(pkt.tcp.srcport) if pkt.tcp.srcport.isdigit() else None,
								'tcp_dstport': int(pkt.tcp.dstport) if pkt.tcp.dstport.isdigit() else None
							})
						except Exception as e:
							logging.warning(f"⚠ Error extracting TCP fields: {e}")
							packet_data.update({
								'tcp_seq': None,
								'tcp_ack': None,
								'tcp_window': None,
								'tcp_flags': None
							})

					if hasattr(pkt, 'tls'):
						packet_data.update({
							'tls_handshake_type': int(pkt.tls.handshake_type) if hasattr(pkt.tls,
																						 'handshake_type') else None,
							'tls_cipher_suite': pkt.tls.cipher_suite if hasattr(pkt.tls, 'cipher_suite') else None
						})

					if hasattr(pkt, 'dns'):
						packet_data['dns_query'] = pkt.dns.qry_name if hasattr(pkt.dns, 'qry_name') else None

					# Calculate inter-packet time
					if previous_timestamp:
						packet_data['inter_packet_time'] = packet_data['timestamp'] - previous_timestamp
					else:
						packet_data['inter_packet_time'] = None
					previous_timestamp = packet_data['timestamp']

					# Track flow size and volume
					flow_key = (packet_data['ip_src'], packet_data['ip_dst'], packet_data['transport'])
					if flow_key not in flows:
						flows[flow_key] = {'size': 0, 'volume': 0, 'packet_count': 0}
					flows[flow_key]['size'] += 1
					flows[flow_key]['volume'] += packet_data['packet_size'] if packet_data['packet_size'] else 0
					flows[flow_key]['packet_count'] += 1
					packet_data['flow_size'] = flows[flow_key]['size']
					packet_data['flow_volume'] = flows[flow_key]['volume']
					packet_data['packets_per_flow'] = flows[flow_key]['packet_count']

					# TCP retransmissions detection
					if 'tcp_seq' in packet_data and packet_data['tcp_seq'] in flows:
						packet_data['tcp_retransmissions'] = flows[packet_data['tcp_seq']]['size']
					else:
						packet_data['tcp_retransmissions'] = 0
					flows[packet_data['tcp_seq']] = {'size': 1}

					# TLS Certificate Info
					if hasattr(pkt, 'tls') and hasattr(pkt.tls, 'handshake_certificate'):
						packet_data['tls_cert_subject'] = pkt.tls.handshake_certificate_subject if hasattr(pkt.tls,
																										   'handshake_certificate_subject') else None
						packet_data['tls_cert_issuer'] = pkt.tls.handshake_certificate_issuer if hasattr(pkt.tls,
																										 'handshake_certificate_issuer') else None

					# HTTP Headers
					if hasattr(pkt, 'http'):
						packet_data['http_host'] = pkt.http.host if hasattr(pkt.http, 'host') else None
						packet_data['http_user_agent'] = pkt.http.user_agent if hasattr(pkt.http,
																						'user_agent') else None

					# Calculate payload entropy
					if hasattr(pkt, 'data') and hasattr(pkt.data, 'data'):
						raw_payload = bytes.fromhex(pkt.data.data.replace(':', ''))
						packet_data['payload_entropy'] = entropy.shannon_entropy(raw_payload)
					else:
						packet_data['payload_entropy'] = None

					packets.append(packet_data)
				except Exception as e:
					#logging.warning(f"⚠ Error processing packet: {e}")
					continue

			cap.close()
			logging.info("🔚 Closing the PCAP file.")
			df = pd.DataFrame(packets)
			logging.info("📊 Converting packet data to DataFrame.")

			# Convert numeric columns properly
			numeric_columns = ['packet_size', 'tcp_seq', 'tcp_ack', 'tcp_window', 'tcp_flags', 'tls_handshake_type',
							   'inter_packet_time', 'flow_size', 'flow_volume', 'packets_per_flow',
							   'tcp_retransmissions']
			for col in numeric_columns:
				if col in df.columns:
					df[col] = pd.to_numeric(df[col], errors='coerce')

			# Handle categorical columns
			categorical_columns = ['protocol', 'ip_src', 'ip_dst', 'transport', 'tls_version', 'tls_cipher_suite',
								   'dns_query']
			for col in categorical_columns:
				if col in df.columns:
					df[col] = df[col].astype(str).replace({'nan': 'Unknown', 'None': 'Unknown'})

			logging.info("✅ Final DataFrame preview before saving:")
			logging.info(df.head())
			return df

		except Exception as e:
			logging.error(f"❌ Error reading file {self.pcap_file}: {e}")
			return pd.DataFrame()
