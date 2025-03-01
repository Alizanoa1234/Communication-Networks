import os
import argparse
import pandas as pd
import logging
from file_manager import FileManager
from packet_analyzer import PacketAnalyzer
from traffic_visualizer import TrafficVisualizer

# Configure logging for structured output
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Define data directories
DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), '..', 'results')


def process_pcap_file(pcap_file, save_csv):
	"""Processes a single PCAPNG file: extracts data, saves CSV, and generates graphs."""
	app_name = os.path.splitext(os.path.basename(pcap_file))[0]
	pcap_path = os.path.join(DATA_DIR, pcap_file)

	logging.info(f"📂 Accessing file: {pcap_path}")

	# Validate and handle potential file issues
	try:
		FileManager.validate_file(pcap_path)
	except Exception as e:
		logging.error(f"❌ Error validating file {pcap_file}: {e}")
		return None

	# Analyze network traffic
	try:
		analyzer = PacketAnalyzer(pcap_path)
		df = analyzer.extract_features()
	except Exception as e:
		logging.error(f"❌ Error reading PCAP {pcap_file}: {e}")
		return None

	if df.empty:
		logging.warning(f"⚠ No data extracted from {pcap_file}. Skipping.")
		return None

	# Save extracted data to CSV if required
	if save_csv:
		csv_filename = f"{app_name}_traffic.csv"
		csv_path = os.path.join(OUTPUT_DIR, csv_filename)
		df.to_csv(csv_path, index=False)
		logging.info(f"💾 Saved CSV file: {csv_path}")

	# Generate traffic visualizations
	try:
		TrafficVisualizer.plot_traffic_characteristics(df, app_name, OUTPUT_DIR)
	except Exception as e:
		logging.error(f"❌ Error generating graphs for {app_name}: {e}")

	return df


def main(input_file=None, save_csv=False):
	"""Processes a single file (if provided) or all PCAP files in the directory."""
	logging.info(f"📂 Ensuring output directory exists: {OUTPUT_DIR}")
	os.makedirs(OUTPUT_DIR, exist_ok=True)

	if not os.path.exists(DATA_DIR) or not os.listdir(DATA_DIR):
		logging.error("⚠ The 'data/' directory is empty or missing. Please add PCAP files.")
		return

	all_dfs = []

	if input_file:
		df = process_pcap_file(input_file, save_csv)
		if df is not None:
			all_dfs.append(df)
	else:
		pcap_files = [f for f in os.listdir(DATA_DIR) if f.endswith(".pcapng")]
		if not pcap_files:
			logging.error("⚠ No PCAP files found in 'data/' directory.")
			return

		for pcap_file in pcap_files:
			df = process_pcap_file(pcap_file, save_csv)
			if df is not None:
				all_dfs.append(df)

	# Generate statistical summary of extracted data
	if all_dfs:
		full_df = pd.concat(all_dfs, ignore_index=True)
		logging.info("📊 Statistical summary of extracted data:")
		logging.info(full_df.describe().to_string())


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Network Traffic Analysis and Classification")
	parser.add_argument("-i", "--input", type=str,
						help="Process a single PCAPNG file (if not provided, all will be processed)")
	parser.add_argument("--save-csv", action="store_true", help="Save extracted data to a CSV file")
	args = parser.parse_args()

	main(args.input, args.save_csv)
