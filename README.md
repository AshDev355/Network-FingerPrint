# Network Fingerprint Generator & Website Behavior Profiler

A web-based cybersecurity and networking tool that captures live network traffic from websites, analyzes packet behavior, and generates unique network fingerprints for educational and traffic analysis purposes.

---

## 📌 Project Overview

The Network Fingerprint Generator captures and analyzes network traffic while a user visits a website. It extracts meaningful packet-level features and generates a behavioral fingerprint summarizing how the website communicates over the network.

The project helps students and cybersecurity learners understand real-world network behavior by comparing traffic patterns of different websites such as streaming platforms, social media sites, news pages, and API-heavy applications.

---

## 🚀 Features

- Live packet capture using Scapy
- Website traffic analysis
- Protocol distribution analysis
- Packet size statistics
- Traffic timeline visualization
- DNS and IP tracking
- Website behavior classification
- Side-by-side website comparison
- PCAP file generation
- Interactive frontend with Chart.js

---

## 🛠️ Technology Stack

- Python 3
- Flask – Backend API server
- Scapy – Packet sniffing and analysis
- HTML/CSS/JavaScript – Frontend UI
- Chart.js – Data visualization
- Socket Programming – DNS/IP resolution

---

## 📂 Project Structure

```bash
network_fingerprint/
│
├── app.py
├── capture.py
├── extract.py
├── fingerprint.py
├── classify.py
├── templates/
├── static/
├── temp/
└── requirements.txt
```

---

## ⚙️ How It Works

1. User enters a website URL.
2. Backend resolves the domain to IP addresses.
3. Traffic is generated toward the target website.
4. Scapy captures packets during the session.
5. Captured packets are saved as `.pcap` files.
6. Features are extracted from packets.
7. A network fingerprint is generated.
8. Website behavior is classified.
9. Results and graphs are displayed in the browser.

---

## 📊 Extracted Features

- Total packets captured
- Protocol distribution
- Packet sizes
- Mean/min/max packet size
- Total bytes transferred
- Destination IP addresses
- DNS queries
- Packet inter-arrival times

---

## 🧠 Website Classification

The system classifies websites into categories such as:

- Streaming
- Social Media
- Static Content
- API-Heavy
- Unknown

---

## 📈 Visualizations

The frontend displays:

- Protocol Pie Chart
- Packet Size Histogram
- Traffic Timeline Graph
- Website Comparison Charts

---

## ▶️ Installation

Clone the repository:

```bash
git clone https://github.com/AshDev355/Network-FingerPrint.git
```

Move into the project folder:

```bash
cd Network-FingerPrint
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the Flask server:

```bash
python app.py
```

---

## ⚠️ Important Note

This project is intended strictly for educational and authorized research purposes. Only capture and analyze traffic on networks and systems you own or have permission to monitor.

Unauthorized packet sniffing may violate privacy laws and cybersecurity regulations.

---

## 🎯 Educational Objectives

This project demonstrates:

- Packet sniffing
- Network traffic analysis
- Protocol behavior
- PCAP processing
- Cybersecurity fundamentals
- Real-world networking concepts

---

## 👨‍💻 Author

Developed by Ayesha Tariq for educational and learning purposes.
