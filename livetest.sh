#!/bin/bash

# Define the file with the list of domains
DOMAINS_FILE=$1

# Check if the file exists
if [[ ! -f "$DOMAINS_FILE" ]]; then
    echo "File not found: $DOMAINS_FILE"
    exit 1
fi

# Function to check if a domain is live
check_domain() {
    domain=$1
    # Remove carriage return '\r'
    domain=${domain//$'\r'/}
    # Ping the domain with a timeout of 5 seconds
    # Only one ping packet is sent to make the script faster
    if ping -c 1 -W 5 "$domain" > /dev/null 2>&1; then
        echo "$domain"
    fi
}

# Read each domain from the file and check if it's live
while IFS= read -r domain || [[ -n "$domain" ]]; do
    # Pass the domain to the check function
    check_domain "$domain"
done < "$DOMAINS_FILE"