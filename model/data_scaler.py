from sklearn.preprocessing import StandardScaler

class DataScaler:
    """
    Applies StandardScaler to normalize feature values.
    """

    def __init__(self, df, feature_columns):
        self.df = df
        self.feature_columns = [col for col in feature_columns if col in df.columns]
        self.scaler = StandardScaler()

    def scale_features(self):
        """Standardizes only the existing numerical feature columns."""
        if not self.feature_columns:
            print("Warning: No valid features available for scaling.")
            return self.df

        self.df[self.feature_columns] = self.scaler.fit_transform(self.df[self.feature_columns])
        print("Feature scaling completed.")
        return self.df
