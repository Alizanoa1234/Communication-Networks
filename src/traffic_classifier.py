import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv2D, MaxPooling2D, Flatten, Dense

class TrafficClassifier:
    @staticmethod
    def train_random_forest(X, y, output_dir):
        """
        Trains a Random Forest classifier on extracted traffic features.
        Saves the trained model in the specified output directory.
        """
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
        clf = RandomForestClassifier(n_estimators=100, random_state=42)
        clf.fit(X_train, y_train)
        joblib.dump(clf, f"{output_dir}/random_forest_model.pkl")
        return clf

    @staticmethod
    def build_cnn_model(input_shape, num_classes):
        """
        Builds and compiles a Convolutional Neural Network (CNN) model.
        """
        model = Sequential([
            Conv2D(32, (3, 3), activation='relu', input_shape=input_shape),
            MaxPooling2D((2, 2)),
            Flatten(),
            Dense(128, activation='relu'),
            Dense(num_classes, activation='softmax')
        ])
        model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
        return model
