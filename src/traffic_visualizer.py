import matplotlib.pyplot as plt
import seaborn as sns
import os
import numpy as np


class TrafficVisualizer:
    @staticmethod
    def plot_traffic_characteristics(df, app_name, output_dir):
        """
        Generates histograms for TCP and TLS header fields.
        """
        if df.empty:
            print(f"⚠ No data available to plot for {app_name}.")
            return

        os.makedirs(output_dir, exist_ok=True)

        # TCP Sequence Number Distribution (Fix x-axis labels)
        if 'tcp_seq' in df.columns and df['tcp_seq'].dropna().size > 0:
            plt.figure(figsize=(12, 5))
            sns.histplot(df['tcp_seq'].dropna(), bins=50, kde=True, color='blue')

            plt.title(f'TCP Sequence Number Distribution - {app_name}')
            plt.xlabel('TCP Sequence Number')
            plt.ylabel('Count')

            # Fix x-axis: Show fewer labels and rotate them
            min_val = df['tcp_seq'].min()
            max_val = df['tcp_seq'].max()
            plt.xticks(np.linspace(min_val, max_val, num=10, dtype=int), rotation=45)

            plt.savefig(f"{output_dir}/{app_name}_tcp_seq.png")
            plt.close()

        # TCP Window Size Distribution (Fix x-axis labels)
        if 'tcp_window' in df.columns and df['tcp_window'].dropna().size > 0:
            plt.figure(figsize=(12, 5))
            sns.histplot(df['tcp_window'].dropna(), bins=50, kde=True, color='red')

            plt.title(f'TCP Window Size Distribution - {app_name}')
            plt.xlabel('TCP Window Size')
            plt.ylabel('Count')

            # Fix x-axis: Show fewer labels and rotate them
            min_val = df['tcp_window'].min()
            max_val = df['tcp_window'].max()
            plt.xticks(np.linspace(min_val, max_val, num=10, dtype=int), rotation=45)

            plt.savefig(f"{output_dir}/{app_name}_tcp_window.png")
            plt.close()
