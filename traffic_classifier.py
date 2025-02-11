import os
import sys
import pyshark
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
from keras import Sequential
from keras.src.layers import Dense, Flatten, MaxPooling2D, Conv2D
from matplotlib import pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix



class TrafficClassifier:
    @staticmethod
    def train_random_forest(X, y, output_dir):
        # Train Random Forest classifier and display performance
        if X.empty:
            print("No data available for training Random Forest.")
            return None

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
        clf = RandomForestClassifier(n_estimators=100, random_state=42)
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)

        print("Random Forest Classification Report:")
        print(classification_report(y_test, y_pred))
        sns.heatmap(confusion_matrix(y_test, y_pred), annot=True, fmt='d')
        plt.title('Confusion Matrix')
        plt.savefig(os.path.join(output_dir, 'random_forest_confusion_matrix.png'))
        plt.close()
        print(f"Random Forest accuracy: {clf.score(X_test, y_test):.2f}")

        # Save the trained model
        joblib.dump(clf, os.path.join(output_dir, 'random_forest_model.pkl'))
        return clf

    @staticmethod
    def build_cnn_model(input_shape, num_classes):
        # Build CNN model for FlowPic classification
        model = Sequential([
            Conv2D(32, (3, 3), activation='relu', input_shape=input_shape),
            MaxPooling2D((2, 2)),
            Conv2D(64, (3, 3), activation='relu'),
            MaxPooling2D((2, 2)),
            Flatten(),
            Dense(128, activation='relu'),
            Dense(num_classes, activation='softmax')
        ])

        model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
        return model