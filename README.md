# QUICKCHECK: Triage Automation Tool

**Author:** Kerolos Farid

A powerful and simple **Bash script** designed to automate the **initial analysis (Triage)** of common security indicators (IPs, Domains, File Hashes). This tool significantly speeds up the workflow for **SOC T1 Analysts** during incident response by providing rapid threat intelligence.

## ✨ Features

* **Quick API Lookups:** Uses the **VirusTotal Public API** for fast reputation checks.
* **Color-Coded Output:** Provides clear, immediate feedback using green (OK) and red (ALERT) terminal colors.
* **Professional Branding:** Displays a clean tool banner and author credit (**Kerolos Farid**).
* **Dependency Checking:** Automatically verifies that essential tools (`curl` and `jq`) are installed before execution.

## 🛠️ Prerequisites

To run QUICKCHECK, you must have the following on your Linux (Ubuntu) or macOS system:

1.  **`curl`** and **`jq`** installed.
    * *Installation on Ubuntu:* `sudo apt install jq`
2.  A free or paid **VirusTotal API Key**.

## 🚀 Installation and Setup

1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/Kerolos-Farid-1/QUICKCHECK.git](https://github.com/Kerolos-Farid-1/QUICKCHECK.git)
    cd QUICKCHECK
    ```
2.  **Grant Execution Permissions:**
    ```bash
    chmod +x quickcheck.sh
    ```
3.  **Set Your API Key (CRITICAL!):**
    For security, set your VirusTotal API key as an environment variable. **Do NOT place your key inside the script file.**

    ```bash
    export VT_API_KEY='YOUR_VIRUSTOTAL_API_KEY_HERE'
    # (Optional: To make it permanent, add this line to your ~/.bashrc file)
    ```

## 📖 Usage Examples

Execute the script using `./quickcheck.sh` followed by an option and the indicator.

| Indicator Type | Option | Example Command |
| :--- | :--- | :--- |
| **IP Address** | `-i` or `--ip` | `./quickcheck.sh -i 8.8.8.8` |
| **Domain** | `-i` or `--ip` | `./quickcheck.sh --ip example.com` |
| **File Hash** | `-h` or `--hash` | `./quickcheck.sh -h d41d8cd98f00b204e9800998ecf8427e` |

## 💡 Future Enhancements

* Integrate the **AbuseIPDB** API for broader IP context.
* Add a feature to output results to a timestamped log file for audit purposes.
* Implement a check for Malicious URLs.
