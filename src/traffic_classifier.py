import joblib
import pandas as pd


class TrafficClassifier:
	def _init_(self, model_path, feature_columns):
		"""Initialize the classifier with the trained model and feature columns"""
		self.model = joblib.load(model_path)  # Load the trained model
		self.feature_columns = feature_columns  # Features used for classification

	def classify_comparison_data(self, comparison_csv):
		"""Send the data from the compare CSV to the model for classification"""
		# Step 1: Load the data
		df_comparison = pd.read_csv(comparison_csv)
		print("🔹 Loading data from CSV...", comparison_csv)

		# Step 2: Check if the relevant columns exist
		missing_columns = [col for col in self.feature_columns if col not in df_comparison.columns]
		if missing_columns:
			print(f"❌ Missing columns: {missing_columns}")
			return

		# Step 3: Prepare the data
		X = df_comparison[self.feature_columns]

		# Step 4: Classification
		predictions = self.model.predict(X)

		# Step 5: Add the predictions to the DataFrame
		df_comparison['Predicted_Type'] = predictions

		# Step 6: Display the res
		print("🔹 Model prediction res:")
		print(df_comparison[['TYPE', 'Predicted_Type']])

		# Optionally, save the res to a new CSV file
		output_csv = comparison_csv.replace("comparison_results.csv", "classified_results.csv")
		df_comparison.to_csv(output_csv, index=False)
		print(f"✅ Results saved in file: {output_csv}")

	def evaluate_predictions(self, df_comparison):
		"""Compare predictions with the actual values"""
		if 'TYPE' not in df_comparison.columns:
			print("⚠ 'TYPE' column not found in data! Cannot compare predictions.")
			return

		# Comparing predictions with the 'TYPE' column
		correct_predictions = df_comparison['Predicted_Type'] == df_comparison['TYPE']
		accuracy = correct_predictions.mean()
		print(f"✅ Accuracy of predictions: {accuracy:.2f}")

		# Show the confusion matrix if necessary
		from sklearn.metrics import confusion_matrix
		import matplotlib.pyplot as plt
		import seaborn as sns

		cm = confusion_matrix(df_comparison['TYPE'], df_comparison['Predicted_Type'])
		plt.figure(figsize=(6, 6))
		sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=self.model.classes_,
					yticklabels=self.model.classes_)
		plt.xlabel("Predicted Label")
		plt.ylabel("True Label")
		plt.title("Confusion Matrix")
		plt.show()