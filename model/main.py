# main.py - Entry point for data processing (Steps 1-4 only)
import os
from model.data_loader import DataLoader
from model.data_splitter import DataSplitter
from model.feature_engineering import FeatureEngineer
from model.data_cleaner import DataCleaner
from model.data_scaler import DataScaler
from model.train_model import ModelTrainer

# Define file path
data_file_path = "../processed_data/HTTPS-clf-dataset.csv"

# Step 1: Load Data
data_loader = DataLoader(data_file_path)
df = data_loader.load_data()
if df is None:
    exit()

# Step 2: Feature Engineering
feature_engineer = FeatureEngineer(df)
df = feature_engineer.extract_features()
if df is None:
    exit()


# Step 3: Data Cleaning
feature_columns = ["BYTES", "BYTES_REV", "PACKETS", "PACKETS_REV", "PKT_LENGTHS_MEAN", "INTERVALS_MEAN"]
data_cleaner = DataCleaner(df, feature_columns)
df = data_cleaner.clean_data()
if df is None:
    exit()

# Step 4: Scaling Data
feature_columns = ["Flow_Size", "Flow_Volume", "Avg_Packet_Size", "Inter_Packet_Time_Mean"]
existing_features = [col for col in feature_columns if col in df.columns]
if not existing_features:
    print("Error: No valid features found in dataset.")
    exit()

data_scaler = DataScaler(df, existing_features)
df = data_scaler.scale_features()
if df is None:
    exit()

print("Final feature set before splitting data:")
print(df[feature_columns].dtypes)  # לוודא שהכול מספרי
print(df[feature_columns].head())  # לוודא שהנתונים סבירים

# Step 5: Splitting Data
target_column = "TYPE"  # Assuming 'TYPE' is the target for classification
data_splitter = DataSplitter(df, target_column)
X_train, X_test, y_train, y_test = data_splitter.split_data()
if X_train is None:
    exit()

print("Checking data types in X_train before training:")
print(X_train.dtypes)

# Identify columns with object (non-numeric) data
non_numeric_columns = X_train.select_dtypes(include=['object']).columns
if not non_numeric_columns.empty:
    print("Warning: The following columns contain non-numeric values:")
    print(non_numeric_columns)
    print(X_train[non_numeric_columns].head())  # Print first few rows of problematic columns
    exit()  # Stop execution if non-numeric values exist


# Step 6: Training and Evaluating Model
model_trainer = ModelTrainer(X_train, X_test, y_train, y_test)
model_trainer.train()
model_trainer.evaluate()

print("Process completed successfully (Steps 1-6).")