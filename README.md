# *Communication-Networks: Encrypted Traffic Analysis & Classification*

##  *Project Overview*  
This project focuses on **analyzing and classifying encrypted network traffic**.  
By examining **network packet characteristics**, we aim to **identify different applications** such as **Zoom, Spotify, Chrome, and Microsoft Edge** based on their traffic patterns.  

We leverage **machine learning models** and **traffic visualizations** to distinguish encrypted application behaviors.  
The final goal is to explore how attackers might analyze encrypted traffic and implement strategies to **enhance privacy and security**.

---

##  *Project Structure*  
```bash
## Project Structure 
Communication-Networks---final-project/
│── data/                   # Wireshark (.pcapng) files for analysis
│   ├── CHROME.pcapng
│   ├── MICROSOFT EDGE.pcapng
│   ├── SPOTIFY.pcapng
│   └── ZOOM.pcapng
│── model/                  # Contains scripts for data processing and machine learning models
│   ├── data_cleaner.py     # Cleans and processes raw packet data
│   ├── data_loader.py      # Loads traffic data into usable formats
│   ├── data_splitter.py    # Splits data for training/testing models
│   ├── main.py             # Main script for analyzing and processing traffic data
│   ├── my_trained_model.pkl # Trained model for traffic classification
│   └── train_model.py      # Trains the machine learning model
│── processed_data/         # Databases
│   ├── data_with_new_features.csv # Filtered data
│   └── dataset.csv # Original data
│── res/                # Stores graphs, res, and comparison files
│   ├── CSV_files/
│   │   ├── 2ZOOM_parsed_data.csv
│   │   ├── CHROME_parsed_data.csv
│   │   ├── SPOTIFY_parsed_data.csv
│   │   └── ZOOM_parsed_data.csv
│   └── Graphs/
│       ├── comparison_flow_size.png
│       ├── comparison_packet_size.png
│       └── feature_correlation_heatmap.png
│── src/                    # Source code for traffic analysis and visualization
│   ├── compare.py          # Script for comparing traffic features
│   ├── data_processor.py   # Processes raw packet data
│   ├── file_manager.py     # Handles file operations & validation
│   ├── main.py             # Main script for processing traffic data
│   ├── packet_analyzer.py  # Extracts features from network packets
│   ├── traffic_classifier.py # Classifies traffic into different application types
│   ├── traffic_visualizer.py # Generates graphs for traffic analysis
│── tests/                  # Unit tests for different modules
│   └── test_parser.py      # Tests for packet data parsing
│── README.md               # Project documentation
│── requirements.txt        # Python dependencies


---
```
---

## *Extracted Traffic Features*
The project extracts and analyzes critical network traffic features to classify encrypted traffic:

- Packet Size Distribution - Analyzing packet size variations.
- TCP Header Fields - Includes sequence number, acknowledgment, window size, and flags.
- TLS Features - Examines TLS handshake types and cipher suites used in encrypted communication.
- Inter-Packet Time Analysis - Measuring time gaps between packets.
- TCP vs UDP Ratio - Understanding the primary transport layer protocol used.
- Flow-Based Analysis - Measuring flow size and volume across different applications.


---

## How to Run the Project

### 1️⃣ Install Dependencies  
Ensure Python is installed. Then, install all required dependencies:

bash
pip install -r requirements.txt


### 2️⃣ Process a Single .pcapng File  
To analyze a specific Wireshark capture file:

bash
python src/main.py -i data/ZOOM.pcapng -o results/ -a Zoom


### 3️⃣ Process All .pcapng Files  
To analyze and extract data from all recorded Wireshark captures:

bash
python src/main.py


### 4️⃣ Generate Comparison Graphs  
After extracting data, generate comparison graphs for different applications:

bash
python src/traffic_visualizer.py


### Using the Terminal or main in src  
You can also use the *main.py* in *src* for data processing and analysis. There is an option to choose whether to *analyze new captures* or *classify data from an existing file*.

---

## The Generated Graphs

The analysis produces visualizations that help understand network traffic behavior and identify applications:

- *Packet Size Distributions*: Each graph shows the packet size distribution for each application. These graphs help understand whether the application's traffic consists mostly of small or large packets and identify unique patterns for each application.

- *TCP Trends – Sequence Numbers and Flags*: These graphs track sequence and acknowledgment numbers for each application and provide insights into TCP behavior.

- *TLS Handshake Types*: Graphs showing the types of handshakes performed during encrypted connections. These help identify applications that establish many secure connections.

- *Traffic Volume per Application*: These graphs show the total traffic volume for each application, helping to understand which application consumes more traffic (in bytes) on the network.

- *Feature Correlation Heatmap*: A heatmap showing the correlation between different traffic features, such as packet size, flow volume, and time between packets. The heatmap helps to understand how different factors are related.

---

## Machine Learning Classification

The project includes *machine learning models* to classify network traffic into different applications (e.g., Zoom, Spotify, Chrome, Microsoft Edge). The traffic features mentioned above serve as inputs to the model, 
which learns to identify patterns in the data that are unique to each application.

The model used in the project is a *Random Forest model*.

### Training the Model:
- Data is processed using *data_cleaner.py* and *data_loader.py*.
- The model is trained using *train_model.py, where different machine learning algorithms (such as **Random Forest*) are applied.
- The trained model is saved in *my_trained_model.pkl* and can be used for real-time traffic classification.

---

## Attack Analysis

The project discusses *attack analysis* of encrypted traffic in a theoretical manner.This analysis helps to understand how attackers might attempt to infer applications in the case of encryption.

---

## Contributors  
- Aliza Feldstein  
- Sapir Bakshi Atias

---
This project provides an in-depth analysis of encrypted network traffic.
By combining data science, network forensics, and machine learning, we gain insights into how applications behave on the network.



