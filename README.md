# *Communication-Networks: Encrypted Traffic Analysis & Classification*

##  *Project Overview*  
This project focuses on **analyzing and classifying encrypted network traffic**.  
By examining **network packet characteristics**, we aim to **identify different applications** such as **Zoom, Spotify, Chrome, and Microsoft Edge** based on their traffic patterns.  

We leverage **machine learning models** and **traffic visualizations** to distinguish encrypted application behaviors.  
The final goal is to explore how attackers might analyze encrypted traffic and implement strategies to **enhance privacy and security**.

---

##  *Project Structure*  
```bash
Communication-Networks---final-project/
│── data/                   # Wireshark (.pcapng) files for analysis
│── notebooks/              # Jupyter notebooks for additional insights
│── results/                # Generated graphs, models, and comparison results
│── src/                    # Source code for traffic analysis
│    ├── main.py            # Main script to process traffic data
│    ├── file_manager.py    # Handles file operations & validation
│    ├── packet_analyzer.py # Extracts features from network packets
│    ├── traffic_visualizer.py # Generates graphs for traffic analysis
│    ├── traffic_classifier.py # Machine learning models for classification
│── tests/                  # Unit tests for different modules
│── README.md               # Project documentation
│── requirements.txt        # Python dependencies
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

## *How to Run the Project*
1️⃣ Install Dependencies
Ensure you have Python installed. Then, install all required dependencies:

sh
Copy
Edit

pip install -r requirements.txt

2️⃣ Process a Single .pcapng File
To analyze a specific Wireshark capture file:

sh
Copy
Edit
python src/main.py -i data/ZOOM.pcapng -o results/ -a Zoom

3️⃣ Process All .pcapng Files
To analyze and extract data from all recorded Wireshark captures:

sh
Copy
Edit
python src/main.py

4️⃣ Generate Comparison Graphs
After extracting data, generate comparison graphs for different applications:

sh
Copy
Edit
python src/traffic_visualizer.py

---

## *Generated Graphs*

The analysis produces visualizations that help understand network traffic behavior:

Packet Size Distributions - Understanding packet size variations.
TCP Window & Sequence Number Trends  - Analyzing TCP behavior.
TLS Handshake Types - Insights into encrypted traffic security.
Traffic Volume per Application - Comparing different applications.
Each graph helps us classify applications and detect network behavior patterns.

---

## *Machine Learning Classification*

---
## *Attacker Analysis*

---
This project provides an in-depth analysis of encrypted network traffic.
By combining data science, network forensics, and machine learning, we gain insights into how applications behave on the network.