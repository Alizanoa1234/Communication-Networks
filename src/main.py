import argparse
import os
import sys

# Ensure src is recognized as a module
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.file_manager import FileManager
from src.packet_analyzer import PacketAnalyzer
from src.traffic_classifier import TrafficClassifier
from src.traffic_visualizer import TrafficVisualizer

def main(input_file, output_dir, app_name):
    """
    Main function for network traffic analysis and classification.
    """
    FileManager.validate_file(input_file)  # Check if file exists
    os.makedirs(output_dir, exist_ok=True)

    print(f"📊 Analyzing packets from {input_file}...")
    analyzer = PacketAnalyzer(input_file)
    df = analyzer.extract_features()

    if df.empty:
        print("⚠ No data available for analysis.")
        return

    print(f"📈 Generating traffic graphs for {app_name}...")
    TrafficVisualizer.plot_traffic_characteristics(df, app_name, output_dir)

    print(f"🧠 Training Random Forest classifier...")
    X = df[['packet_size']].fillna(0)
    y = [0] * len(X)  # Placeholder labels, should be updated for real classification
    TrafficClassifier.train_random_forest(X, y, output_dir)

    print("✅ Analysis and classification completed!")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Network Traffic Analysis and Classification")
    parser.add_argument('-i', '--input', type=str, default="data/הקלטה SPOTIFY.pcapng", help="PCAP file")
    parser.add_argument('-o', '--output', type=str, default='./results', help="Output directory")
    parser.add_argument('-a', '--app', type=str, required=True, help="Application name")
    args = parser.parse_args()

    main(args.input, args.output, args.app)

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


