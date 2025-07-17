# Anomaly Detector 🔍

This is a simple anomaly detection script that identifies outliers in a numerical dataset using Z-score based analysis.

## 🔧 Features
- Detects anomalies based on standard deviation and z-score thresholds
- CLI interface with argument parsing
- Outputs summary of normal vs. anomalous data points

## 🧪 Example Use Case
This tool can be used to:
- Flag suspicious login attempts
- Detect usage spikes in web traffic logs
- Identify anomalies in system metrics

## 🚀 How to Use

### 1. Install dependencies:
```bash
pip install -r requirements.txt
```

### 2. Run the script:
```bash
python anomaly_detection.py --input data.csv --column "response_time"
```

> You can also test it interactively with mock data or modify the script to support log ingestion.

## ⚙️ Arguments
| Argument      | Description                                  |
|---------------|----------------------------------------------|
| `--input`     | Path to CSV file with numerical data         |
| `--column`    | Column name to analyze for anomalies         |
| `--threshold` | Z-score threshold (default: 3.0)             |

## 📁 Files
- `anomaly_detection.py` — Main detection logic
- `requirements.txt` — Required Python libraries
- `.gitignore` — Skips uploading junk/system files

## 📜 License
MIT License — Free to use, modify, and share.

---

### 🤝 Contributions Welcome!
Feel free to fork, open issues, or suggest improvements.
