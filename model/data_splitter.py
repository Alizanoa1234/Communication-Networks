from sklearn.model_selection import train_test_split

class DataSplitter:
    """
    Splits dataset into training and testing sets.
    """

    def __init__(self, df, target_column):
        self.df = df
        self.target_column = target_column

    def split_data(self, test_size=0.2, random_state=42):
        """Splits data into train and test sets."""
        if self.target_column not in self.df.columns:
            print(f"Error: Target column '{self.target_column}' not found in dataset.")
            return None, None, None, None

        X = self.df.drop(columns=[self.target_column])
        y = self.df[self.target_column]
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=random_state)
        print("Data split into training and testing sets.")
        return X_train, X_test, y_train, y_test
