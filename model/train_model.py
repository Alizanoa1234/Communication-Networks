import os
import pickle

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

class ModelTrainer:
    def _init_(self, X_train, X_test, y_train, y_test):
        """
        Initializes the ModelTrainer with training and testing data.
        """
        self.X_train = X_train
        self.X_test = X_test
        self.y_train = y_train
        self.y_test = y_test
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)

    def train(self):
        """
        Trains the RandomForestClassifier model using the provided training data.
        """
        print("\n🔹 Step: Training the Model")
        print(f"🔹 Training set shape: {self.X_train.shape}, Labels shape: {self.y_train.shape}")


        try:
            print("🔹 Before training, model:", self.model)
            self.model.fit(self.X_train, self.y_train)
            print("🔹 After training, model:", self.model)

            os.makedirs("model", exist_ok=True)

            path = os.path.abspath("model/my_trained_model.pkl")
            with open(path, 'wb') as f:
                pickle.dump(self.model, f)
            print(f"Model saved at: {path}")
            print("✅ Model saved successfully!")
        except Exception as e:
            print(f"❌ Error during model training or saving: {e}")


        accuracy_train = self.model.score(self.X_train, self.y_train)
        print(f"Model training accuracy: {accuracy_train:.2f}")
        return self.model


    def evaluate(self):
        """
        Evaluates the model on the test set and prints performance metrics.
        """
        print("\n🔹 Step: Evaluating Model")
        y_pred = self.model.predict(self.X_test)

        # Calculate accuracy
        accuracy = self.model.score(self.X_test, self.y_test)
        print(f"✅ Model Accuracy: {accuracy:.2f}")

        # Print classification report (Precision, Recall, F1-score)
        print("\n🔹 Classification Report:")
        print(classification_report(self.y_test, y_pred, target_names=['D', 'L', 'M', 'P', 'U', 'W']))

        # Display confusion matrix
        print("\n🔹 Confusion Matrix:")
        cm = confusion_matrix(self.y_test, y_pred)
        plt.figure(figsize=(6, 6))
        sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                    xticklabels=['D', 'L', 'M', 'P', 'U', 'W'],
                    yticklabels=['D', 'L', 'M', 'P', 'U', 'W'])
        plt.xlabel("Predicted Label")
        plt.ylabel("True Label")
        plt.title("Confusion Matrix")
        plt.show()

        # Check label distribution in train and test sets
        print("\n🔹 Checking Label Distribution in Train and Test Sets")
        train_distribution = self.y_train.value_counts(normalize=True)
        test_distribution = self.y_test.value_counts(normalize=True)

        print("\n🔹 Training Set Distribution:")
        print(train_distribution)

        print("\n🔹 Test Set Distribution:")
        print(test_distribution)

        # Plot distribution of labels in train and test sets
        fig, ax = plt.subplots(1, 2, figsize=(12, 5))

        sns.barplot(x=train_distribution.index, y=train_distribution.values, ax=ax[0])
        ax[0].set_title("Train Set Distribution")
        ax[0].set_xlabel("Category")
        ax[0].set_ylabel("Percentage")

        sns.barplot(x=test_distribution.index, y=test_distribution.values, ax=ax[1])
        ax[1].set_title("Test Set Distribution")
        ax[1].set_xlabel("Category")
        ax[1].set_ylabel("Percentage")

        plt.show()