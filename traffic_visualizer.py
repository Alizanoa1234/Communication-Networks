from matplotlib import pyplot as plt
import os
import sys
import pyshark
import pandas as pd
import seaborn as sns
import numpy as np


class TrafficVisualizer:
    @staticmethod
    def plot_traffic_characteristics(df, app_name, output_dir):
        # Plot packet size and inter-arrival time distributions
        if df.empty:
            print(f"No data to plot for {app_name}.")
            return

        plt.figure(figsize=(12, 6))
        sns.histplot(df['packet_size'], kde=True, bins=50)
        plt.title(f'Packet Size Distribution - {app_name}')
        plt.xlabel('Packet Size (bytes)')
        plt.ylabel('Frequency')
        plt.savefig(os.path.join(output_dir, f'{app_name}_packet_size_distribution.png'))
        plt.close()

        plt.figure(figsize=(12, 6))
        sns.histplot(df['inter_arrival_time'], kde=True, bins=50)
        plt.title(f'Inter-arrival Time Distribution - {app_name}')
        plt.xlabel('Inter-arrival Time (seconds)')
        plt.ylabel('Frequency')
        plt.savefig(os.path.join(output_dir, f'{app_name}_inter_arrival_distribution.png'))
        plt.close()

    @staticmethod
    def create_flowpic_images(df, output_dir, app_name):
        # Create FlowPic image based on packet size and inter-arrival time
        if df.empty:
            print(f"No data to create FlowPic for {app_name}.")
            return np.zeros((1500, 1500))

        size_bins = np.linspace(0, 1500, 150)
        time_bins = np.linspace(0, df['inter_arrival_time'].max(), 150)

        hist, _, _ = np.histogram2d(df['packet_size'], df['inter_arrival_time'], bins=[size_bins, time_bins])
        plt.imshow(hist.T, origin='lower', aspect='auto', cmap='hot')
        plt.title(f'FlowPic for {app_name}')
        plt.xlabel('Packet Size')
        plt.ylabel('Inter-arrival Time')
        plt.colorbar()
        plt.savefig(os.path.join(output_dir, f'{app_name}_flowpic.png'))
        plt.close()

        return hist.T