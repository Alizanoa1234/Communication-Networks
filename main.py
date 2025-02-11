from file_manager import FileManager
from packet_analyzer import PacketAnalyzer
from traffic_classifier import TrafficClassifier
from traffic_visualizer import TrafficVisualizer
import numpy as np
import os
import tensorflow as tf
import sys
import pyshark
import pandas as pd
import argparse
from tensorflow.python.keras.utils.np_utils import to_categorical
import matplotlib.pyplot as plt
import seaborn as sns


class TrafficAnalysisApp:
    def __init__(self, input_file, output_dir, app_name):
        self.input_file = input_file
        self.output_dir = output_dir
        self.app_name = app_name
        # Mapping applications to numerical labels for classification
        self.label_map = {'App1': 0, 'App2': 1, 'App3': 2, 'App4': 3}

    def run(self):
        FileManager.validate_file(self.input_file)
        os.makedirs(self.output_dir, exist_ok=True)

        print(f"Extracting features from {self.input_file}...")
        analyzer = PacketAnalyzer(self.input_file)
        df = analyzer.extract_features()

        if df.empty:
            print("No data extracted. Exiting.")
            return

        print(f"Plotting traffic characteristics for {self.app_name}...")
        TrafficVisualizer.plot_traffic_characteristics(df, self.app_name, self.output_dir)

        print(f"Generating FlowPic for {self.app_name}...")
        flowpic_image = TrafficVisualizer.create_flowpic_images(df, self.output_dir, self.app_name)

        print(f"Preparing data for classification...")
        X = df[['packet_size', 'inter_arrival_time']].fillna(0)
        y = [self.label_map.get(self.app_name, 0)] * len(X)

        print("Training Random Forest classifier...")
        TrafficClassifier.train_random_forest(X, y, self.output_dir)

        print("Training CNN for FlowPic classification...")
        flowpic_image = np.expand_dims(flowpic_image, axis=(0, -1))
        y_cnn = to_categorical([self.label_map.get(self.app_name, 0)], num_classes=len(self.label_map))
        model = TrafficClassifier.build_cnn_model(flowpic_image.shape[1:], num_classes=len(self.label_map))
        model.fit(flowpic_image, y_cnn, epochs=5)
        model.save(os.path.join(self.output_dir, 'cnn_model.h5'))  # Save CNN model

        print("Analysis and classification completed.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Network Traffic Analysis and Classification")
    parser.add_argument('-i', '--input', type=str, required=True, help="Input pcap file")
    parser.add_argument('-o', '--output', type=str, default='./res', help="Output directory for results")
    parser.add_argument('-a', '--app', type=str, required=True, choices=['App1', 'App2', 'App3', 'App4'], help="Application name for labeling")
    args = parser.parse_args()

    app = TrafficAnalysisApp(args.input, args.output, args.app)
    app.run()



