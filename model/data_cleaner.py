import pandas as pd
class DataCleaner:
    """
    Handles missing values and cleans only relevant dataset columns.
    """

    def __init__(self, df, feature_columns):
        self.df = df
        self.feature_columns = feature_columns

    def clean_data(self):
        """Cleans only the columns used in feature selection."""
        try:
            self.df = self.df.dropna(subset=self.feature_columns)  # Remove rows with NaN only in relevant columns

            # Convert relevant columns to numeric
            for col in self.feature_columns:
                self.df[col] = pd.to_numeric(self.df[col], errors='coerce')

            print("Relevant data cleaned successfully.")
            return self.df
        except Exception as e:
            print(f"Error during data cleaning: {e}")
            return None
