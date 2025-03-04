import pandas as pd
import os


class DataLoader:
	"""
    Loads dataset from the processed_data folder and prepares it as a DataFrame.
    Supports both CSV and JSON formats.
    """

	def __init__(self, file_path):
		self.file_path = file_path

	def load_data(self):
		"""Reads CSV or JSON file and returns a pandas DataFrame."""
		if not os.path.exists(self.file_path):
			print(f"Error: File not found at {self.file_path}")
			return None

		try:
			if self.file_path.endswith(".csv"):
				df = pd.read_csv(self.file_path)
			elif self.file_path.endswith(".json"):
				df = pd.read_json(self.file_path)
			else:
				print("Unsupported file format. Use CSV or JSON.")
				return None

			print("Data loaded successfully.")
			return df

		except Exception as e:
			print(f"Error loading data: {e}")
			return None
