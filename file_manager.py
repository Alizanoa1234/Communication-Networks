import os
import sys
import pyshark
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv2D, MaxPooling2D, Flatten, Dense
from tensorflow.keras.utils import to_categorical
import argparse
import joblib  # For saving models
class FileManager:
    @staticmethod
    def validate_file(file_path):
        # Check if the file exists, exit if it doesn't
        if not os.path.isfile(file_path):
            print(f"Error: File {file_path} does not exist.")
            sys.exit(1)