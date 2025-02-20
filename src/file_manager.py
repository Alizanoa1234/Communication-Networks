import os
import sys

class FileManager:
    @staticmethod
    def validate_file(file_path):
        """
        Checks if the given file exists.
        Exits the program if the file is not found.
        """
        if not os.path.isfile(file_path):
            print(f"❌ Error: File {file_path} not found.")
            sys.exit(1)
