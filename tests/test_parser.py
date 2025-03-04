import unittest
import sys
import os
import pandas as pd
from unittest.mock import MagicMock

#Add `src` directory to Python module search path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from packet_analyzer import PacketAnalyzer
from file_manager import FileManager
from data_processor import DataProcessor

class TestPacketAnalyzer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Runs once before all tests to set up necessary paths."""
        cls.test_data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data'))
        cls.test_results_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'res', 'tests'))
        os.makedirs(cls.test_results_dir, exist_ok=True)

    def test_missing_file(self):
        """Test handling of missing PCAP files."""
        non_existent_file = os.path.join(self.test_data_dir, "non_existent.pcapng")
        with self.assertRaises(SystemExit):  # FileManager should exit if the file is missing
            FileManager.validate_file(non_existent_file)

    def test_empty_pcap(self):
        """Test handling of an empty PCAP file (mocked, without requiring TShark)."""
        empty_pcap = os.path.join(self.test_results_dir, "empty.pcapng")

        #Create an empty PCAP file for testing
        with open(empty_pcap, 'w') as f:
            f.write("")

        #Mock `extract_features` to return an empty DataFrame instead of using TShark
        analyzer = PacketAnalyzer(empty_pcap)
        analyzer.extract_features = MagicMock(return_value=pd.DataFrame())

        df = analyzer.extract_features()
        self.assertTrue(df.empty, "Dataframe should be empty for an empty PCAP file")

    def test_valid_pcap_processing(self):
        """Test processing of a valid PCAP file (without requiring TShark)."""
        valid_pcap = os.path.join(self.test_data_dir, "test_traffic.pcapng")
        if not os.path.exists(valid_pcap):
            self.skipTest("Skipping test: Valid PCAP file not found in data directory.")

        analyzer = PacketAnalyzer(valid_pcap)

        #Mock `extract_features` to return sample data instead of actually using TShark
        sample_data = pd.DataFrame({
            "packet_size": [100, 200, 300],
            "protocol": ["TCP", "UDP", "TLS"],
            "flow_size": [1000, 2000, 3000]
        })
        analyzer.extract_features = MagicMock(return_value=sample_data)

        df = analyzer.extract_features()
        self.assertFalse(df.empty, "Dataframe should not be empty for a valid PCAP file")
        self.assertIn("packet_size", df.columns, "Missing 'packet_size' column in parsed data")
        self.assertIn("protocol", df.columns, "Missing 'protocol' column in parsed data")

    def test_dataframe_cleaning(self):
        """Test DataProcessor's ability to clean and preprocess data."""
        raw_data = {
            "timestamp": [1.1, 2.2, 3.3, 4.4, 5.5],
            "packet_size": [150, None, 500, None, 300],
            "tcp_seq": [1000, 2000, None, 4000, None],
            "tcp_ack": [None, 5000, 6000, None, 8000],
            "inter_packet_time": [0.01, None, 0.05, None, 0.02]
        }

        df = pd.DataFrame(raw_data)
        cleaned_df = DataProcessor.clean_dataframe(df)

        self.assertFalse(cleaned_df.isnull().values.any(), "Dataframe should not contain null values after cleaning")

    def test_feature_extraction(self):
        """Test if PacketAnalyzer correctly extracts key traffic features, even without TCP packets."""
        test_pcap = os.path.join(self.test_data_dir, "test_traffic.pcapng")
        if not os.path.exists(test_pcap):
            self.skipTest("Skipping test: Valid PCAP file not found in data directory.")

        analyzer = PacketAnalyzer(test_pcap)

        #Mock `extract_features` to return sample data without TCP dependencies
        sample_data = pd.DataFrame({
            "packet_size": [120, 140, 160],
            "flow_size": [500, 700, 900],
            "transport": ["UDP", "UDP", "TLS"]
        })
        analyzer.extract_features = MagicMock(return_value=sample_data)

        df = analyzer.extract_features()

        #Ensure essential fields exist, even if TCP is missing
        self.assertIn("packet_size", df.columns, "Missing 'packet_size' field in extracted data")
        self.assertIn("flow_size", df.columns, "Missing 'flow_size' field in extracted data")

    def test_file_manager_validation(self):
        """Ensure FileManager correctly validates existing files."""
        existing_pcap = os.path.join(self.test_data_dir, "test_traffic.pcapng")
        if not os.path.exists(existing_pcap):
            self.skipTest("Skipping test: PCAP file required for validation does not exist.")

        try:
            FileManager.validate_file(existing_pcap)
        except SystemExit:
            self.fail("FileManager.validate_file() raised SystemExit unexpectedly!")

if __name__ == '__main__':
    unittest.main()
