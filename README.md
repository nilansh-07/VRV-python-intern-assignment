# Log Analysis System

## Overview
A comprehensive log analysis tool designed to process web server logs and extract insights about traffic patterns, potential security threats, and usage statistics. This system generates both HTML and CSV reports, offering clear and interactive data visualization.

---

## Key Features

- **IP Traffic Analysis**: Summarizes the request frequency per IP address.
- **Endpoint Monitoring**: Highlights the most frequently accessed endpoints.
- **Security Analysis**: Identifies suspicious activity, such as multiple failed login attempts.

### Output Formats
- **HTML Reports**: Interactive, visually appealing reports.
- **CSV Exports**: Raw data for in-depth processing.
- **Terminal Output**: Quick summary for instant analysis.

---

## Technical Implementation

- Developed in Python using standard libraries.
- Utilizes `collections.Counter` for efficient data aggregation.
- Employs regex for precise log parsing.
- Generates responsive HTML reports with modern CSS styling.

---

## Sample Output

The system provides the following analyses:

1. **Requests Per IP**: Displays traffic distribution across IP addresses.
2. **Popular Endpoints**: Identifies the most accessed URLs.
3. **Security Alerts**: Flags suspicious activities, such as repeated failed login attempts.

---

## Setup and Installation

### Prerequisites

- Python 3.6 or higher
- Git (optional, for cloning)

### Installation Steps

1. **Get the Code:**

   ```bash
   # Option 1: Clone with Git
   git clone https://github.com/nilansh-07/VRV-python-intern-assessment.git
   cd web-log-analysis-system

   # Option 2: Download ZIP
   # Download and extract the ZIP file from the repository
   ```

2. **Install Dependencies:**

   ```bash
   pip install prettytable
   ```

---

## How to Use

### Input

- The system processes web server logs in the standard Apache or Nginx format.
- A sample log file (`sample.log`) is included for testing.
- Replace `sample.log` with your own log file in the same format.

### Processing

1. Place your log file in the project directory.
2. Run the analysis script:

   ```bash
   python web_log_analysis.py
   ```

The script performs:
- Request frequency analysis.
- Endpoint usage tracking.
- Security threat detection.

### Output Options

- **HTML Reports**:
  - Open `web_log_analysis_report.html` in a web browser.
  - Or use the command: `start web_log_analysis_report.html`.

- **CSV Export**:
  - View raw data in `web_log_analysis_results.csv` for further analysis.

- **Terminal Output**:
  - Instant overview of key metrics displayed in the console.

---

## License
This project is free to use and modify. Contributions are welcome to enhance functionality or fix issues.
