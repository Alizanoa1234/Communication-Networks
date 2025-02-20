import matplotlib.pyplot as plt
import seaborn as sns

class TrafficVisualizer:
    @staticmethod
    def plot_traffic_characteristics(df, app_name, output_dir):
        """
        Generates histograms for packet sizes and saves the plots with improved visualization.
        """
        if df.empty:
            print(f"⚠ No data available to plot for {app_name}.")
            return

        plt.figure(figsize=(12, 6))
        sns.histplot(df['packet_size'], kde=True, bins=50, color='blue', alpha=0.6)

        plt.title(f'Packet Size Distribution - {app_name}', fontsize=14)
        plt.xlabel('Packet Size (Bytes)', fontsize=12)
        plt.ylabel('Frequency (Count)', fontsize=12)
        plt.grid(True)

        plt.savefig(f"{output_dir}/{app_name}_packet_size.png")
        plt.close()
