import os
import argparse
import pickle
from pathlib import Path
import pandas as pd
from file_manager import FileManager
from packet_analyzer import PacketAnalyzer
from traffic_classifier import TrafficClassifier
from traffic_visualizer import TrafficVisualizer
import joblib

# Define data directories
BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
RESULTS_DIR = BASE_DIR / "res"
CSV_DIR = RESULTS_DIR / "CSV_files"
GRAPH_DIR = RESULTS_DIR / "Graphs"
COMPARE_DIR = RESULTS_DIR / "Graphs/compare"

# Define required columns for comparison CSV
REQUIRED_COLUMNS = [
	"TYPE", "Avg_Packet_Size",
    "Flow_Size (Bytes)", "Flow_Volume (Packets)", "Inter_Packet_Time_Mean"
]


def process_pcap_file(pcap_file):
	"""Process a single .pcapng file, extract data, and generate graphs"""
	app_name = os.path.splitext(pcap_file)[0]  # Extract the application name from the file
	pcap_path = os.path.join(DATA_DIR, pcap_file)

	print(f"📊 Processing {pcap_file}...")

	# Validate and analyze the file
	FileManager.validate_file(pcap_path)
	analyzer = PacketAnalyzer(pcap_path)
	df = analyzer.extract_features()

	if df.empty:
		print(f"⚠ No data extracted from {pcap_file}. Skipping...")
		return None

	#Check if TCP columns exist before accessing them
	if 'tcp_flags' in df.columns:
		df['tcp_flags'] = df['tcp_flags'].fillna("None")  # Handle missing TCP flags
	else:
		df['tcp_flags'] = "None"  # If no TCP traffic, set a default value

	#Handle RTT only if inter_packet_time & tcp_flags exist
	if 'inter_packet_time' in df.columns and 'tcp_flags' in df.columns:
		df['rtt'] = df.apply(lambda row: row['inter_packet_time'] if row.get('tcp_flags') == 16 else None, axis=1)
	else:
		df['rtt'] = None  # Default when no TCP exists

	#Prevent division by zero when calculating Packet Loss Rate
	total_packets = df['flow_volume'].sum() if 'flow_volume' in df.columns else 0
	packet_loss_rate = 1 - (df.shape[0] / total_packets) if total_packets > 0 else 0  # Prevent zero division

	#Compute key metrics safely
	comparison_data = {
		"TYPE": app_name,
		"Avg_Packet_Size": df['packet_size'].mean() if 'packet_size' in df.columns else None,
		"TCP_Seq_Count": df['tcp_seq'].nunique() if 'tcp_seq' in df.columns else None,
		"TCP_Window_Size_Avg": df['tcp_window'].mean() if 'tcp_window' in df.columns else None,
		"TLS_Handshake_Count": df['tls_handshake_type'].nunique() if 'tls_handshake_type' in df.columns else None,
		"Primary_Protocol": df['transport'].mode()[0] if 'transport' in df.columns else "Unknown",
		"Flow_Size (Bytes)": df['flow_size'].sum() if 'flow_size' in df.columns else None,
		"Flow_Volume (Packets)": df['flow_volume'].sum() if 'flow_volume' in df.columns else None,
		"Inter_Packet_Time_Mean": df['inter_packet_time'].mean() if 'inter_packet_time' in df.columns else None,
		"TLS_Version": df['tls_version'].mode()[0] if 'tls_version' in df.columns else "Unknown",
		"TLS_Cipher_Suite": df['tls_cipher_suite'].mode()[0] if 'tls_cipher_suite' in df.columns else "Unknown",
		"Packet_Loss_Rate": packet_loss_rate,
		"Flow_Size": df['packet_size'].sum() if 'packet_size' in df.columns else None,
		"RTT": df['rtt'].mean() if 'rtt' in df.columns else None,  # ✅ Now safely handled
		"TCP_Flags": df['tcp_flags'].mode()[0] if 'tcp_flags' in df.columns else "Unknown"  # ✅ Handle missing TCP flags
	}

	#Generate graphs for the application
	TrafficVisualizer.plot_traffic_characteristics(df, app_name, GRAPH_DIR)

	return comparison_data

def menu():
	"""Interactive menu to choose an option"""
	print("Choose an option:")
	print("1. Analysis only")
	print("2. Classification only")
	print("3. Both Analysis and Classification")
	choice = input("Enter the number of your choice: ")

	if choice == "1":
		print("Running analysis only...")
		main(action_type="analysis")
	elif choice == "2":
		print("Running classification only...")
		main(action_type="classification")
	elif choice == "3":
		print("Running both analysis and classification...")
		main(action_type="both")
	else:
		print("Invalid choice. Please select 1, 2, or 3.")


def main(input_file=None, action_type="classification"):
	"""Runs analysis on a single file (if specified) or processes all .pcapng files.
	action_type determines which operation to run: 'both', 'classification', or 'analysis'."""

	# Ensure necessary directories exist
	os.makedirs(RESULTS_DIR, exist_ok=True)
	os.makedirs(CSV_DIR, exist_ok=True)
	os.makedirs(GRAPH_DIR, exist_ok=True)
	os.makedirs(COMPARE_DIR, exist_ok=True)

	results = []

	if action_type == "both" or action_type == "analysis":
		# Run the application analysis (graphs and files generation)
		if input_file:
			results.append(process_pcap_file(input_file))
		else:
			# Process all .pcapng files in the directory
			pcap_files = [f for f in os.listdir(DATA_DIR) if f.endswith(".pcapng")]
			if not pcap_files:
				print("⚠ No .pcapng files found in data/ directory. Please add some recordings.")
				return
			for pcap_file in pcap_files:
				result = process_pcap_file(pcap_file)
				if result:
					results.append(result)

	if action_type == "both" or action_type == "classification":
		# Skip processing PCAP files and directly classify using comparison CSV
		comparison_csv = os.path.join(CSV_DIR, "comparison_results.csv")
		if os.path.exists(comparison_csv):
			# Load the model using pickle
			model_path = os.path.join(os.path.dirname(os.getcwd()), 'model/my_trained_model.pkl')
			try:
				with open(model_path, 'rb') as f:
					model = pickle.load(f)
					print("✅ Model loaded successfully.")
			except Exception as e:
				print(f"❌ Error loading the model: {e}")

				return

			# Create classifier and perform classification
			classifier = TrafficClassifier(model=model, feature_columns=[
				"Flow_Size (Bytes)", "Flow_Volume (Packets)", "Avg_Packet_Size", "Inter_Packet_Time_Mean"])
			classifier.classify_comparison_data(comparison_csv)
			df_comparison = pd.read_csv(comparison_csv)
			classifier.evaluate_predictions(df_comparison)
		else:
			print("⚠ No comparison res CSV found, skipping classification.")

	if action_type == "analysis":
		# If only analysis is required, skip classification
		print("✅ Analysis completed! No classification was performed.")


if __name__ == "__main__":
	menu()