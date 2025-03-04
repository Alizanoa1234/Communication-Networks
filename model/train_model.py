from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

class ModelTrainer:
    """
    Trains and evaluates a machine learning model.
    """
    def __init__(self, X_train, X_test, y_train, y_test):
        self.X_train = X_train
        self.X_test = X_test
        self.y_train = y_train
        self.y_test = y_test
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)

    def train(self):
        """Trains the model on the training data."""
        self.model.fit(self.X_train, self.y_train)
        print("Model training completed.")

    def evaluate(self):
        """Evaluates model performance on test data."""
        y_pred = self.model.predict(self.X_test)
        accuracy = accuracy_score(self.y_test, y_pred)
        print(f"Model Accuracy: {accuracy:.2f}")
