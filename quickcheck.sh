#!/bin/bash
#
# QUICKCHECK Tool for T1 Analysts
# Author: Kerolos Farid
# Description: Automates the initial Triage process for IPs, Hashes, and Domains.
# License: MIT
#
# Usage: 
# 1. Set API Key: export VT_API_KEY='YourKey'
# 2. Run: ./quickcheck.sh -i 8.8.8.8
# 3. Run: ./quickcheck.sh -h d41d8cd98f00b204e9800998ecf8427e

# --- Variables & Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# --- Configuration ---
# The script relies on the environment variable VT_API_KEY being set by the user.
VT_API_KEY="${VT_API_KEY}"

# --- Functions ---

# 1. Prints the professional ASCII banner and author details (Kerolos Farid)
print_banner() {
    echo -e "${YELLOW}
|     QUICK-CHECK     |
|     Version 1.0     |

    ${GREEN}:: QUICKCHECK - SOC Triage Automation Tool ::${NC}
    ${YELLOW}:: Authored by: Kerolos Farid ${NC}
    -----------------------------------------------------
"
}

# 2. Checks for required system dependencies (curl and jq)
check_dependencies() {
    if ! command -v curl &> /dev/null
    then
        echo -e "${RED}[!] ERROR: curl is not installed. Please install it to continue.${NC}"
        exit 1
    fi
    if ! command -v jq &> /dev/null
    then
        echo -e "${RED}[!] ERROR: The 'jq' tool is not installed.${NC}"
        echo -e "    'jq' is essential for parsing JSON API responses."
        echo -e "    Install it using: sudo apt-get install jq (on Debian/Ubuntu)"
        exit 1
    fi
}

# 3. Checks an IP address or Domain using VirusTotal
check_ip_domain() {
    local indicator="$1"
    echo -e "\n[+] Running VirusTotal Check for: ${YELLOW}$indicator${NC}"

    if [ -z "$VT_API_KEY" ]; then
        echo -e "${RED}[!] ERROR: VT_API_KEY environment variable is not set.${NC}"
        echo "    Please set it using: export VT_API_KEY='YourKey'"
        return
    fi

    # API Call
    VT_RESPONSE=$(curl -s --request GET \
      --url "https://www.virustotal.com/api/v3/ip_addresses/$indicator" \
      --header "x-apikey: $VT_API_KEY")

    # Error checking
    if echo "$VT_RESPONSE" | grep -q "error"; then
        echo -e "${RED}[!] Error during API call. Response: ${NC}$(echo "$VT_RESPONSE" | jq -r '.error.message')"
        return
    fi

    # Parse and display the data
    HARMFUL=$(echo "$VT_RESPONSE" | jq -r '.data.attributes.last_analysis_stats.malicious + .data.attributes.last_analysis_stats.suspicious')
    TOTAL=$(echo "$VT_RESPONSE" | jq -r '.data.attributes.last_analysis_stats.harmless + .data.attributes.last_analysis_stats.malicious + .data.attributes.last_analysis_stats.suspicious')
    COUNTRY=$(echo "$VT_RESPONSE" | jq -r '.data.attributes.country')

    echo "    - Total Scanners Checked: $TOTAL"
    # تم التعديل: تطبيق اللون الأحمر على قيمة المتغير فقط
    echo -e "    - Malicious/Suspicious Detections: ${RED}$HARMFUL${NC}"
    echo "    - Associated Country: $COUNTRY"

    if [ "$HARMFUL" -gt 0 ]; then
        echo -e "    ${RED}[ALERT] This indicator is flagged as Malicious/Suspicious!${NC}"
    else
        echo -e "    ${GREEN}[OK] Currently no major flags.${NC}"
    fi
}

# 4. Checks a File Hash (MD5, SHA1, SHA256) using VirusTotal
check_file_hash() {
    local hash="$1"
    echo -e "\n[+] Running VirusTotal Hash Check for: ${YELLOW}$hash${NC}"

    if [ -z "$VT_API_KEY" ]; then
        echo -e "${RED}[!] ERROR: VT_API_KEY environment variable is not set.${NC}"
        echo "    Please set it using: export VT_API_KEY='YourKey'"
        return
    fi

    # API Call
    VT_RESPONSE=$(curl -s --request GET \
      --url "https://www.virustotal.com/api/v3/files/$hash" \
      --header "x-apikey: $VT_API_KEY")

    # Error checking
    if echo "$VT_RESPONSE" | grep -q "error"; then
        echo -e "${RED}[!] Error during API call. Response: ${NC}$(echo "$VT_RESPONSE" | jq -r '.error.message')"
        return
    fi

    # Parse and display the data
    HARMFUL=$(echo "$VT_RESPONSE" | jq -r '.data.attributes.last_analysis_stats.malicious + .data.attributes.last_analysis_stats.suspicious')
    
    # تم التعديل: تطبيق اللون الأحمر على قيمة المتغير فقط
    echo -e "    - Malicious Detections: ${RED}$HARMFUL${NC}"
    
    if [ "$HARMFUL" -gt 0 ]; then
        echo -e "    ${RED}[ALERT] This File Hash is known to be Malicious!${NC}"
    else
        echo -e "    ${GREEN}[OK] Currently no major flags.${NC}"
    fi
}

# 5. Displays the usage instructions
usage() {
    echo "Usage: $0 [OPTION] <INDICATOR>"
    echo " "
    echo "Options:"
    echo "  -i, --ip        Check an IP address or Domain."
    echo "  -h, --hash      Check a File Hash (MD5, SHA1, SHA256)."
    echo " "
    echo "Prerequisite: Set your VT API key: export VT_API_KEY='YourKey'"
    exit 1
}


# --- Main Logic ---

# 1. Run dependencies check
check_dependencies

# 2. Print the banner 
print_banner

# 3. Check for arguments
if [ "$#" -eq 0 ]; then
    usage
fi

# 4. Parse options and execute the check
case "$1" in
    -i|--ip)
        if [ -z "$2" ]; then usage; fi
        check_ip_domain "$2"
        ;;
    -h|--hash)
        if [ -z "$2" ]; then usage; fi
        check_file_hash "$2"
        ;;
    *)
        usage
        ;;
esac

exit 0
