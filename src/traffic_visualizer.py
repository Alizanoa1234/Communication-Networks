import matplotlib.pyplot as plt
import seaborn as sns
import os
import numpy as np
import pandas as pd


class TrafficVisualizer:
    @staticmethod
    def plot_traffic_characteristics(df, app_name, output_dir):
        """
        Generates histograms for TCP and TLS header fields.
        """
        if df.empty:
            print(f"⚠ No data available to plot for {app_name}.")
            return

        app_graph_dir = os.path.join(output_dir, app_name)
        os.makedirs(app_graph_dir, exist_ok=True)

        # Packet Size Distribution - Shows the distribution of packet sizes in bytes.
        # Helps in understanding the nature of traffic (small vs. large packets).
        plt.figure(figsize=(12, 5))
        sns.histplot(df['packet_size'].dropna(), bins=50, kde=True, color='blue')
        plt.title(f'Packet Size Distribution - {app_name}')
        plt.xlabel('Packet Size (Bytes)')
        plt.ylabel('Count')
        plt.savefig(f"{app_graph_dir}/{app_name}_packet_size.png")
        plt.close()

        # TCP Flags Distribution - Displays how often each TCP flag appears in the traffic.
        # Useful for detecting SYN, ACK, FIN, and other control messages in the flow.
        if 'tcp_flags' in df.columns and df['tcp_flags'].dropna().size > 0:
            plt.figure(figsize=(12, 5))
            sns.countplot(x=df['tcp_flags'].dropna(), color='orange')
            plt.title(f'TCP Flags Distribution - {app_name}')
            plt.xlabel('TCP Flags (Bit Values)')
            plt.ylabel('Count')
            plt.savefig(f"{app_graph_dir}/{app_name}_tcp_flags.png")
            plt.close()

        # TLS Handshake Type Distribution - Shows the types of TLS handshakes that occurred.
        # Important for analyzing encrypted traffic and security protocols in use.
        if 'tls_handshake_type' in df.columns and df['tls_handshake_type'].dropna().size > 0:
            plt.figure(figsize=(12, 5))
            sns.countplot(x=df['tls_handshake_type'].dropna(), color='green')
            plt.title(f'TLS Handshake Types - {app_name}')
            plt.xlabel('Handshake Type')
            plt.ylabel('Count')
            plt.savefig(f"{app_graph_dir}/{app_name}_tls_handshake.png")
            plt.close()

        # TLS Version Distribution - Displays the versions of TLS used in the captured traffic.
        # Useful for checking security compliance and identifying outdated protocols.
        if 'tls_version' in df.columns and df['tls_version'].dropna().size > 0:
            plt.figure(figsize=(12, 5))
            sns.countplot(x=df['tls_version'].dropna(), color='blue')
            plt.title(f'TLS Versions Used - {app_name}')
            plt.xlabel('TLS Version')
            plt.ylabel('Count')
            plt.savefig(f"{app_graph_dir}/{app_name}_tls_version.png")
            plt.close()

        # Time Series of Packet Sizes - Plots packet size changes over time.
        # Helps in detecting burst traffic, network congestion, or consistent data flow.
        plt.figure(figsize=(12, 6))
        plt.plot(df['timestamp'], df['packet_size'], marker='o', linestyle='-', markersize=2)
        plt.title(f'Time Series of Packet Sizes - {app_name}')
        plt.xlabel('Timestamp')
        plt.ylabel('Packet Size (Bytes)')
        plt.grid(True)
        plt.savefig(f"{app_graph_dir}/{app_name}_time_series.png")
        plt.close()

        # Inter-Packet Time Distribution - Shows the time gaps between consecutive packets.
        # Helps in detecting network jitter, delays, or unusual transmission patterns.
        plt.figure(figsize=(10, 6))
        sns.boxplot(y=df['inter_packet_time'].dropna())
        plt.title(f'Inter-Packet Time Distribution - {app_name}')
        plt.ylabel('Inter-Packet Time (Seconds)')
        plt.grid(True)
        plt.savefig(f"{app_graph_dir}/{app_name}_inter_packet_time_boxplot.png")
        plt.close()

        # TCP/UDP Ratio - Compares the number of TCP and UDP packets.
        # Useful for identifying whether the traffic is more reliable (TCP) or low-latency (UDP).
        protocol_counts = df['transport'].value_counts()
        plt.figure(figsize=(8, 5))
        sns.barplot(x=protocol_counts.index, y=protocol_counts.values)
        plt.title(f'TCP/UDP Ratio - {app_name}')
        plt.xlabel('Protocol')
        plt.ylabel('Count')
        plt.savefig(f"{app_graph_dir}/{app_name}_tcp_udp_ratio.png")
        plt.close()


    @staticmethod
    def compare_results(csv_file, output_dir="res/graphs/compare/"):
        """
        Generates comparison bar charts from the res CSV file.
        """
        if not os.path.exists(csv_file):
            print("⚠ No comparison CSV file found. Run the analysis first.")
            return

        df = pd.read_csv(csv_file)

        os.makedirs(output_dir, exist_ok=True)

        # Set a larger figure size for readability
        plt.figure(figsize=(12, 6))

        # Compare Average Packet Sizes - Shows the average packet size for each application.
        # Helps in understanding whether an application transmits small or large packets.
        plt.figure(figsize=(10, 5))
        sns.barplot(x="Application", y="Avg_Packet_Size", hue="Application", data=df, palette="Blues_r", legend=False)
        plt.title("Average Packet Size Comparison")
        plt.title("Average Packet Size Comparison")
        plt.ylabel("Packet Size (Bytes)")
        plt.xticks(rotation=45)
        plt.savefig(os.path.join(output_dir, "comparison_packet_size.png"))
        plt.close()

        # Compare TCP Sequence Number Counts
        # plt.figure(figsize=(10, 5))
        # sns.barplot(x="Application", y="TCP_Seq_Count", data=df, palette="Reds_r")
        # plt.title("TCP Sequence Number Count Comparison")
        # plt.ylabel("Unique TCP Sequence Numbers")
        # plt.xticks(rotation=45)
        # plt.savefig(os.path.join(output_dir, "comparison_tcp_seq.png"))
        # plt.close()

        # Compare TCP Window Sizes
        # plt.figure(figsize=(10, 5))
        # plt.figure(figsize=(10, 5))
        # sns.barplot(x="Application", y="TCP_Window_Size_Avg", data=df, palette="Greens_r")
        # plt.title("Average TCP Window Size Comparison")
        # plt.ylabel("Window Size")
        # plt.xticks(rotation=45)
        # plt.savefig(os.path.join(output_dir, "comparison_tcp_window.png"))
        # plt.close()

        # Compare TLS Handshake Counts - Shows how many unique TLS handshakes each application used.
        # Helps in identifying secure vs. insecure applications based on handshake behavior.
        plt.figure(figsize=(10, 5))
        sns.barplot(x="Application", y="TLS_Handshake_Count", hue="Application", data=df, palette="Purples_r",legend=False)
        plt.title("TLS Handshake Type Count Comparison")
        plt.ylabel("Count of Unique TLS Handshake Types")
        plt.xticks(rotation=45)
        plt.savefig(os.path.join(output_dir, "comparison_tls_handshake.png"))
        plt.close()

        # Compare Flow Size - Measures total bytes transferred by each application.
        # Helps in understanding which applications are heavy data consumers.
        sns.barplot(x="Application", y="Flow_Size (Bytes)", hue="Application", data=df, palette="coolwarm",legend=False)
        plt.title("Comparison of Flow Size Between Applications")
        plt.ylabel("Total Flow Size (Bytes)")
        plt.xticks(rotation=45)
        plt.savefig(f"{output_dir}/comparison_flow_size.png")
        plt.close()

        # Compare Flow Volume - Shows how many packets each application transmitted.
        # Useful for distinguishing between chatty applications (many small packets) vs. bulk transfers.
        plt.figure(figsize=(12, 6))
        sns.barplot(x="Application", y="Flow_Volume (Packets)", hue="Application", data=df, palette="viridis",legend=False)
        plt.title("Comparison of Flow Volume Between Applications")
        plt.ylabel("Total Flow Volume (Packets)")
        plt.xticks(rotation=45)
        plt.savefig(f"{output_dir}/comparison_flow_volume.png")
        plt.close()

        # Feature Correlation Heatmap - Displays correlations between various traffic attributes.
        # Helps in identifying patterns, such as whether larger packets correlate with longer delays.
        plt.figure(figsize=(10, 8))
        corr = df[['Avg_Packet_Size', 'Inter_Packet_Time_Mean', 'Flow_Size (Bytes)', 'Flow_Volume (Packets)']].corr()
        sns.heatmap(corr, annot=True, cmap="coolwarm", fmt=".2f")
        plt.title("Feature Correlation Heatmap")
        plt.savefig(f"{output_dir}/feature_correlation_heatmap.png")
        plt.close()

        print("✅ Comparison graphs saved in res/ folder.")