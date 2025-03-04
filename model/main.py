from data_loader import DataLoader
from data_cleaner import DataCleaner
from data_splitter import DataSplitter
from train_model import ModelTrainer
import pandas as pd

# Define file paths
data_file_path = "../processed_data/dataset.csv"
data_with_new_features = "../processed_data/data_with_new_features.csv"

# Step 1: Load Data
print("\n🔹 Step 1: Loading Data")
data_loader = DataLoader(data_file_path)
df = data_loader.load_data()
if df is None or df.empty:
    print("❌ Error: Failed to load data or dataset is empty.")
    exit()
print("✅ Data loaded successfully.")
print("🔹 Columns in dataset:", df.columns.tolist())

# Step 2: Data Cleaning - Keep only relevant columns
print("\n🔹 Step 2: Cleaning Data")
relevant_columns = ["BYTES", "BYTES_REV", "PACKETS", "PACKETS_REV", "PKT_LENGTHS_MEAN", "INTERVALS_MEAN", "TYPE"]
data_cleaner = DataCleaner(df, relevant_columns)
df_cleaned = data_cleaner.clean_data()

if df_cleaned is None or df_cleaned.empty:
    print("❌ Error: Data cleaning failed, dataset is empty.")
    exit()

# Ensure TYPE is always a string and handle missing values
df_cleaned["TYPE"] = df_cleaned["TYPE"].astype(str).fillna("Unknown")

print("✅ Data cleaned successfully.")
print("🔹 Missing values in TYPE after cleaning:", df_cleaned["TYPE"].isna().sum())

# Step 3: Feature Engineering - Create new columns
print("\n🔹 Step 3: Creating New Features")
df_cleaned["Flow_Size"] = df_cleaned["BYTES"] + df_cleaned["BYTES_REV"]
df_cleaned["Flow_Volume"] = df_cleaned["PACKETS"] + df_cleaned["PACKETS_REV"]
df_cleaned["Avg_Packet_Size"] = df_cleaned["PKT_LENGTHS_MEAN"]
df_cleaned["Inter_Packet_Time_Mean"] = df_cleaned["INTERVALS_MEAN"]

new_features = ["Flow_Size", "Flow_Volume", "Avg_Packet_Size", "Inter_Packet_Time_Mean"]

# Verify new features were created
missing_features = [col for col in new_features if col not in df_cleaned.columns]
if missing_features:
    print(f"❌ Error: Failed to create new features: {missing_features}")
    exit()
print("✅ New features created successfully.")
print("🔹 First rows of new features:\n", df_cleaned[new_features].head())

# Step 4: Save only new features + target column
df_final = df_cleaned[new_features + ["TYPE"]]

# Verify TYPE is still present
if "TYPE" not in df_final.columns:
    print("❌ Error: TYPE column is missing from the final dataset!")
    exit()
# Step 5: Save processed dataset
print("\n🔹 Step 4: Saving Processed Dataset")
df_final.to_csv(data_with_new_features, index=False)

# Verify the file was saved correctly
try:
    df_check = pd.read_csv(data_with_new_features)
except Exception as e:
    print(f"❌ Error: Failed to save or reload processed dataset. {e}")
    exit()

# ✅ קריאה מחדש של הנתונים בצורה נכונה
df = pd.read_csv(data_with_new_features)

# Define features and target
feature_columns = ["Flow_Size", "Flow_Volume", "Avg_Packet_Size", "Inter_Packet_Time_Mean"]
target_column = "TYPE"

# Ensure TYPE is categorical
df[target_column] = df[target_column].astype(str)

# Splitting Data
print("\n🔹 Step 5: Splitting Data")
data_splitter = DataSplitter(df, target_column)
X_train, X_test, y_train, y_test = data_splitter.split_data()

if X_train is None or X_train.empty:
    print("❌ Error: Data split failed, training set is empty.")
    exit()

print("✅ Data split successfully.")

# Step 6: Train and Evaluate Model
# Filter only the relevant columns
X_train = X_train[feature_columns]
X_test = X_test[feature_columns]


print("\n🔹 Step 6: Training and Evaluating Model")
model_trainer = ModelTrainer(X_train, X_test, y_train, y_test)
model_trainer.train()
model_trainer.evaluate()

print("\n✅ Process completed successfully (Steps 5-6).")