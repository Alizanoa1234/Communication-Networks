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

# Ensure necessary directories exist
os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(CSV_DIR, exist_ok=True)
os.makedirs(GRAPH_DIR, exist_ok=True)
os.makedirs(COMPARE_DIR, exist_ok=True)


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

    # Check if TCP columns exist before accessing them
    if 'tcp_flags' in df.columns:
        df['tcp_flags'] = df['tcp_flags'].fillna("None")
    else:
        df['tcp_flags'] = "None"

    # Handle RTT only if inter_packet_time & tcp_flags exist
    if 'inter_packet_time' in df.columns and 'tcp_flags' in df.columns:
        df['rtt'] = df.apply(lambda row: row['inter_packet_time'] if row.get('tcp_flags') == 16 else None, axis=1)
    else:
        df['rtt'] = None

    # Prevent division by zero when calculating Packet Loss Rate
    total_packets = df['flow_volume'].sum() if 'flow_volume' in df.columns else 0
    packet_loss_rate = 1 - (df.shape[0] / total_packets) if total_packets > 0 else 0

    # Compute key metrics safely
    comparison_data = {
        "Application": app_name,  # Ensure the key is "Application"
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
        "RTT": df['rtt'].mean() if 'rtt' in df.columns else None,
        "TCP_Flags": df['tcp_flags'].mode()[0] if 'tcp_flags' in df.columns else "Unknown"
    }

    # Generate graphs for the application
    TrafficVisualizer.plot_traffic_characteristics(df, app_name, GRAPH_DIR)

    return comparison_data


def menu():
    """Interactive menu to choose an option"""
    print("\nChoose an option:")
    print("1. Analysis only")
    print("2. Classification only")
    print("3. Both Analysis and Classification")

    choice = input("Enter the number of your choice: ").strip()

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
        menu()  # Restart menu on invalid input


def main(input_file=None, action_type=None):
    """Runs analysis on a single file (if specified) or processes all .pcapng files."""

    if action_type is None:
        menu()  # If no action is provided, open the menu.

    results = []
    comparison_csv = os.path.join(CSV_DIR, "comparison_results.csv")

    # Load existing results if the file exists
    if os.path.exists(comparison_csv):
        existing_df = pd.read_csv(comparison_csv)
    else:
        existing_df = pd.DataFrame()

    if action_type == "both" or action_type == "analysis":
        if input_file:
            results.append(process_pcap_file(input_file))
        else:
            pcap_files = [f for f in os.listdir(DATA_DIR) if f.endswith(".pcapng")]
            if not pcap_files:
                print("⚠ No .pcapng files found in data/ directory.")
                return
            for pcap_file in pcap_files:
                result = process_pcap_file(pcap_file)
                if result:
                    results.append(result)

    # Convert new results to DataFrame
    new_results_df = pd.DataFrame(results)

    # Concatenate old and new results, remove duplicates
    if not new_results_df.empty:
        comparison_df = pd.concat([existing_df, new_results_df], ignore_index=True).drop_duplicates()
        comparison_df.to_csv(comparison_csv, index=False)

    if action_type == "both" or action_type == "classification":
        if os.path.exists(comparison_csv):
            model_path = os.path.join(os.path.dirname(os.getcwd()), 'model/my_trained_model.pkl')
            try:
                with open(model_path, 'rb') as f:
                    model = pickle.load(f)
                    print("✅ Model loaded successfully.")
            except Exception as e:
                print(f"❌ Error loading the model: {e}")
                return

            classifier = TrafficClassifier(model=model, feature_columns=[
                "Flow_Size (Bytes)", "Flow_Volume (Packets)", "Avg_Packet_Size", "Inter_Packet_Time_Mean"
            ])
            classifier.classify_comparison_data(comparison_csv)
            df_comparison = pd.read_csv(comparison_csv)
            classifier.evaluate_predictions(df_comparison)
        else:
            print("⚠ No comparison results CSV found, skipping classification.")

    if action_type == "analysis":
        print("✅ Analysis completed! Comparison results saved.")

    print("📊 Generating comparison graphs...")
    TrafficVisualizer.compare_results(comparison_csv)
    print("✅ Comparison graphs saved.")


if __name__ == "__main__":
    menu()
