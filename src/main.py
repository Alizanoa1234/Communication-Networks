import os
import argparse
from pathlib import Path
import pandas as pd
from file_manager import FileManager
from packet_analyzer import PacketAnalyzer
from traffic_visualizer import TrafficVisualizer

# Define data directories
BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
RESULTS_DIR = BASE_DIR / "results"
CSV_DIR = RESULTS_DIR / "CSV_files"
GRAPH_DIR = RESULTS_DIR / "Graphs"
COMPARE_DIR = RESULTS_DIR / "Graphs/compare"

# Define required columns for comparison CSV
REQUIRED_COLUMNS = [
    "Application", "Avg_Packet_Size", "TCP_Seq_Count", "TCP_Window_Size_Avg", "TLS_Handshake_Count",
    "Primary_Protocol", "Flow_Size (Bytes)", "Flow_Volume (Packets)", "Inter_Packet_Time_Mean",
    "TLS_Version", "TLS_Cipher_Suite", "Packet_Loss_Rate", "Flow_Size"
]

def process_pcap_file(pcap_file):
    """Processes a single .pcapng file, extracts data, and generates graphs."""
    app_name = os.path.splitext(pcap_file)[0]  # Extracts application name from the file
    pcap_path = os.path.join(DATA_DIR, pcap_file)

    print(f"📊 Processing {pcap_file}...")

    # Validate and analyze the file
    FileManager.validate_file(pcap_path)
    analyzer = PacketAnalyzer(pcap_path)
    df = analyzer.extract_features()

    if df.empty:
        print(f"⚠ No data extracted from {pcap_file}. Skipping...")
        return None

    # Generate graphs for the application
    TrafficVisualizer.plot_traffic_characteristics(df, app_name, GRAPH_DIR)

    # Compute key metrics for comparison
    comparison_data = {
        "Application": app_name,
        "Avg_Packet_Size": df['packet_size'].mean(),
        "TCP_Seq_Count": df['tcp_seq'].nunique() if 'tcp_seq' in df.columns else None,
        "TCP_Window_Size_Avg": df['tcp_window'].mean() if 'tcp_window' in df.columns else None,
        "TLS_Handshake_Count": df['tls_handshake_type'].nunique() if 'tls_handshake_type' in df.columns else None,
        "Primary_Protocol": df['transport'].mode()[0] if 'transport' in df.columns else "Unknown",
        "Flow_Size (Bytes)": df['flow_size'].sum() if 'flow_size' in df.columns else None,
        "Flow_Volume (Packets)": df['flow_volume'].sum() if 'flow_volume' in df.columns else None,
        "Inter_Packet_Time_Mean": df['inter_packet_time'].mean() if 'inter_packet_time' in df.columns else None,
        "TLS_Version": df['tls_version'].mode()[0] if 'tls_version' in df.columns else "Unknown",
        "TLS_Cipher_Suite": df['tls_cipher_suite'].mode()[0] if 'tls_cipher_suite' in df.columns else "Unknown",
        "Packet_Loss_Rate": 1 - (df.shape[0] / (df['flow_volume'].sum() if 'flow_volume' in df.columns else 1)),
        "Flow_Size": df['packet_size'].sum() if 'packet_size' in df.columns else None  # Newly added Flow_Size metric
    }

    return comparison_data

def main(input_file=None):
    """Runs analysis on a single file (if specified) or processes all .pcapng files."""
    # Ensure necessary directories exist
    os.makedirs(RESULTS_DIR, exist_ok=True)
    os.makedirs(CSV_DIR, exist_ok=True)
    os.makedirs(GRAPH_DIR, exist_ok=True)
    os.makedirs(COMPARE_DIR, exist_ok=True)  # Creates directory for comparison graphs

    results = []

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

    # Save comparison results to CSV
    comparison_csv = os.path.join(CSV_DIR, "comparison_results.csv")
    if results:
        df_comparison = pd.DataFrame(results)

        # Ensure all required columns are present
        for col in REQUIRED_COLUMNS:
            if col not in df_comparison.columns:
                df_comparison[col] = None

        df_comparison.to_csv(comparison_csv, index=False)
        print(f"✅ Analysis completed! Results saved in {comparison_csv}")

    # Generate comparison graphs after CSV creation
    if os.path.exists(comparison_csv):
        print("📊 Generating comparison graphs...")
        TrafficVisualizer.compare_results(comparison_csv, COMPARE_DIR)
    else:
        print("⚠ No comparison CSV found! Skipping comparison graphs.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Traffic Analysis and Classification")
    parser.add_argument("-i", "--input", type=str, help="Process a single .pcapng file (leave empty to process all)")
    args = parser.parse_args()

    main(args.input)
