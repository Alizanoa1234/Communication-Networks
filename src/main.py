import os
import argparse
import pandas as pd
from file_manager import FileManager
from packet_analyzer import PacketAnalyzer
from traffic_visualizer import TrafficVisualizer

# Set directory where .pcapng files are stored
DATA_DIR = "data/"
OUTPUT_DIR = "results/"


def process_pcap_file(pcap_file):
    """Process a single .pcapng file, extract data, and generate graphs."""
    app_name = os.path.splitext(pcap_file)[0]  # Extract app name from file name
    pcap_path = os.path.join(DATA_DIR, pcap_file)

    print(f"📊 Processing {pcap_file}...")

    # Validate and analyze the file
    FileManager.validate_file(pcap_path)
    analyzer = PacketAnalyzer(pcap_path)
    df = analyzer.extract_features()

    if df.empty:
        print(f"⚠ No data extracted from {pcap_file}. Skipping.")
        return None

    # Generate graphs
    TrafficVisualizer.plot_traffic_characteristics(df, app_name, OUTPUT_DIR)

    # Store key metrics
    return {
        "Application": app_name,
        "Avg_Packet_Size": df['packet_size'].mean(),
        "TCP_Seq_Count": df['tcp_seq'].nunique() if 'tcp_seq' in df.columns else None,
        "TCP_Window_Size_Avg": df['tcp_window'].mean() if 'tcp_window' in df.columns else None,
        "TLS_Handshake_Count": df['tls_handshake_type'].nunique() if 'tls_handshake_type' in df.columns else None,
        "Primary_Protocol": df['transport'].mode()[0] if 'transport' in df.columns else "Unknown"
    }


def main(input_file=None):
    """Run analysis on a single file (if specified) or process all .pcapng files."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    results = []

    if input_file:
        # Process a single file
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

    # Save comparison table
    if results:
        df_comparison = pd.DataFrame(results)
        df_comparison.to_csv(os.path.join(OUTPUT_DIR, "comparison_results.csv"), index=False)
        print("✅ Analysis completed! Results saved in results/comparison_results.csv")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Traffic Analysis and Classification")
    parser.add_argument("-i", "--input", type=str, help="Process a single .pcapng file (leave empty to process all)")
    args = parser.parse_args()

    main(args.input)

#the code below is sopoed to work weth there a lot of recording""
# import os
# import argparse
# from src.file_manager import FileManager
# from src.packet_analyzer import PacketAnalyzer
# from src.traffic_visualizer import TrafficVisualizer
#
# def process_pcap(input_file, output_dir, app_name):
#     """Process a single PCAP file and generate visualizations."""
#     FileManager.validate_file(input_file)
#     os.makedirs(output_dir, exist_ok=True)
#
#     print(f"📊 Analyzing {app_name} traffic from {input_file}...")
#     analyzer = PacketAnalyzer(input_file)
#     df = analyzer.extract_features()
#
#     if df.empty:
#         print(f"⚠ No valid packets found in {input_file}. Skipping.")
#         return
#
#     print(f"📈 Generating traffic graphs for {app_name}...")
#     TrafficVisualizer.plot_traffic_characteristics(df, app_name, output_dir)
#
# def main(input_dir, output_dir):
#     """Process all PCAP files in the input directory."""
#     os.makedirs(output_dir, exist_ok=True)
#
#     for file in os.listdir(input_dir):
#         if file.endswith(".pcap") or file.endswith(".pcapng"):
#             app_name = file.split(".")[0]  # Extract app name from file name
#             process_pcap(os.path.join(input_dir, file), output_dir, app_name)
#
# if __name__ == '__main__':
#     parser = argparse.ArgumentParser(description="Analyze multiple PCAP files")
#     parser.add_argument('-i', '--input', type=str, default="data/", help="Directory containing PCAP files")
#     parser.add_argument('-o', '--output', type=str, default='./results', help="Output directory")
#     args = parser.parse_args()
#
#     main(args.input, args.output)






#main the copares the apps import os
# import argparse
# import pandas as pd
# from file_manager import FileManager
# from packet_analyzer import PacketAnalyzer
# from traffic_visualizer import TrafficVisualizer
#
# # List of applications and their corresponding PCAP files
# APPLICATIONS = {
#     "Spotify": "data/הקלטה SPOTIFY.pcapng",
#     "YouTube": "data/youtube.pcapng",
#     "Zoom": "data/zoom.pcapng",
#     "WhatsApp": "data/whatsapp.pcapng",
#     "Google Meet": "data/google_meet.pcapng"
# }
#
# def process_application(app_name, pcap_file, output_dir):
#     """Process a single application and extract network metrics."""
#     print(f"📊 Analyzing packets from {pcap_file}...")
#     FileManager.validate_file(pcap_file)
#     os.makedirs(output_dir, exist_ok=True)
#
#     analyzer = PacketAnalyzer(pcap_file)
#     df = analyzer.extract_features()
#
#     if df.empty:
#         print(f"⚠ No data extracted for {app_name}. Skipping.")
#         return None
#
#     # Generate visualizations
#     TrafficVisualizer.plot_traffic_characteristics(df, app_name, output_dir)
#
#     # Compute summary metrics
#     return {
#         "Application": app_name,
#         "Avg_Packet_Size": df['packet_size'].mean(),
#         "TCP_Seq_Count": df['tcp_seq'].nunique() if 'tcp_seq' in df.columns else None,
#         "TCP_Window_Size_Avg": df['tcp_window'].mean() if 'tcp_window' in df.columns else None,
#         "TLS_Handshake_Count": df['tls_handshake_type'].nunique() if 'tls_handshake_type' in df.columns else None,
#         "Primary_Protocol": df['transport'].mode()[0] if 'transport' in df.columns else "Unknown"
#     }
#
# def main():
#     parser = argparse.ArgumentParser(description="Network Traffic Analysis and Comparison")
#     parser.add_argument('-o', '--output', type=str, default='results', help="Output directory for results")
#     args = parser.parse_args()
#
#     results = []
#     for app_name, pcap_file in APPLICATIONS.items():
#         result = process_application(app_name, pcap_file, args.output)
#         if result:
#             results.append(result)
#
#     # Create and save comparison table
#     df_comparison = pd.DataFrame(results)
#     df_comparison.to_csv(os.path.join(args.output, "comparison_results.csv"), index=False)
#     print("✅ Comparison complete! Results saved in results/comparison_results.csv")
#
# if __name__ == "__main__":
#     main()
#
