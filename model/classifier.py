import pandas as pd
import numpy as np
import os
import joblib
import multiprocessing
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

from model.kaggle_data_processor import MODEL_PATH


class TrafficClassifier:
	"""Handles classification of new data using trained model."""

	def __init__(self, model_path):
		self.model_path = model_path

	def classify_new_data(self, input_file, output_file="results/classification_results.csv"):
		print("🔹 Loading trained model...")
		model = joblib.load(self.model_path)

		print("🔹 Loading new dataset for classification...")
		df = pd.read_csv(input_file)

		X = df.drop(columns=['Application'], errors='ignore')

		print("🔹 Performing classification...")
		df['Predicted_Application'] = model.predict(X)

		# Save results
		os.makedirs(os.path.dirname(output_file), exist_ok=True)
		df.to_csv(output_file, index=False)
		print(f"✅ Classification results saved in {output_file}")

if __name__ == "__main__":
    classifier = TrafficClassifier(MODEL_PATH)
    classifier.classify_new_data("data/new_traffic_data.csv")
