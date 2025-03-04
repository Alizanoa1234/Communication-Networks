import os
import pandas as pd
import logging


class DataProcessor:
	@staticmethod
	def clean_dataframe(df):
		"""Cleans extracted data by handling missing and incorrect values."""
		numeric_columns = ['packet_size', 'tcp_seq', 'tcp_ack', 'tcp_window',
						   'tcp_flags', 'inter_packet_time', 'flow_size', 'flow_volume']

		for col in numeric_columns:
			if col in df.columns:
				median_value = df[col].median()
				df[col] = df[col].fillna(median_value).astype(float)
				df[col] = pd.to_numeric(df[col], errors='coerce')
				if col not in df.columns:
					df[col] = None  # Fill missing columns with default values

		categorical_columns = ['protocol', 'ip_src', 'ip_dst', 'transport', 'tls_version',
							   'tls_cipher_suite', 'tls_handshake_type']

		for col in categorical_columns:
			if col in df.columns:
				df[col] = df[col].fillna("Unknown")

		critical_columns = ['timestamp', 'packet_size']
		df = df.dropna(subset=critical_columns)

		return df

	@staticmethod
	def save_dataframe_to_csv(df, output_csv):
		"""Saves the DataFrame as a CSV file."""
		os.makedirs(os.path.dirname(output_csv), exist_ok=True)
		df.to_csv(output_csv, index=False)
		logging.info(f"✅ CSV cleaned and saved successfully: {output_csv}")
