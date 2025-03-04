class FeatureEngineer:
    """
    Processes raw data and extracts relevant features for model training.
    """

    def __init__(self, df):
        self.df = df

    def extract_features(self):
        """Creates Flow_Size, Flow_Volume, Avg_Packet_Size, Inter_Packet_Time_Mean, RTT."""
        feature_mappings = {
            "Flow_Size": ["BYTES", "BYTES_REV"],
            "Flow_Volume": ["PACKETS", "PACKETS_REV"],
            "Avg_Packet_Size": ["PKT_LENGTHS_MEAN"],
            "Inter_Packet_Time_Mean": ["INTERVALS_MEAN"],
            #"RTT": ["DBI_BRST_DURATION_MEAN"]
        }

        for feature, columns in feature_mappings.items():
            missing_columns = [col for col in columns if col not in self.df.columns]
            if missing_columns:
                print(f"Warning: Missing columns {missing_columns} for '{feature}', skipping this feature.")
                continue  # Skip this feature if required columns are missing

            if len(columns) == 2:
                self.df[feature] = self.df[columns[0]] + self.df[columns[1]]
            else:
                self.df[feature] = self.df[columns[0]]

        print("Feature extraction completed.")
        return self.df
