import re
import pandas as pd

#path for log file
log_file_path = 'sample.log'

# Function to count requests per IP address
def count_requests_per_ip(log_file_path):
    ip_requests = {}
    
    # Read log file
    with open(log_file_path, 'r') as log_file:
        for line in log_file:
            # Extract IP address using regex
            match = re.match(r'(\S+)', line)
            if match:
                ip = match.group(1)
                ip_requests[ip] = ip_requests.get(ip, 0) + 1
    
    # Sort by request count
    sorted_ips = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)
    
    print("\nIP Address           Request Count")
    for ip, count in sorted_ips:
        print(f"{ip:<20} {count}")
    
    return sorted_ips

# Function to identify the most frequently accessed endpoint
def most_accessed_endpoint(log_file_path):
    endpoint_counts = {}
    
    with open(log_file_path, 'r') as log_file:
        for line in log_file:
            # Extract endpoint (URL) using regex
            match = re.search(r'"[A-Z]+\s(/[\w/]+)', line)
            if match:
                endpoint = match.group(1)
                endpoint_counts[endpoint] = endpoint_counts.get(endpoint, 0) + 1
    
    # Identify the most accessed endpoint
    most_accessed = max(endpoint_counts.items(), key=lambda x: x[1])
    
    print(f"\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    return most_accessed

# Function to detect suspicious activity (brute force login attempts)
def detect_suspicious_activity(log_file_path, threshold=10):
    suspicious_ips = {}
    
    with open(log_file_path, 'r') as log_file:
        for line in log_file:
            # Look for failed login attempts (HTTP status 401 or 'Invalid credentials')
            if '401' in line or 'Invalid credentials' in line:
                ip = re.match(r'(\S+)', line).group(1)
                suspicious_ips[ip] = suspicious_ips.get(ip, 0) + 1
    
    # Filter suspicious IPs based on the threshold
    suspicious_ips = {ip: count for ip, count in suspicious_ips.items() if count > threshold}
    
    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20} {count}")
    
    return suspicious_ips

# Function to save the results to CSV
def save_results_to_csv(ip_data, endpoint_data, suspicious_data):
    # Prepare data for CSV
    ip_df = pd.DataFrame(ip_data, columns=["IP Address", "Request Count"])
    endpoint_df = pd.DataFrame([endpoint_data], columns=["Endpoint", "Access Count"])
    suspicious_df = pd.DataFrame(list(suspicious_data.items()), columns=["IP Address", "Failed Login Count"])
    
    # Save to CSV
    with open('log_analysis_results.csv', 'w', newline='') as file:
        ip_df.to_csv(file, index=False, header=True)
        file.write("\n")  
        endpoint_df.to_csv(file, index=False, header=True)
        file.write("\n")  
        suspicious_df.to_csv(file, index=False, header=True)
    
    print("\nResults have been saved to 'log_analysis_results.csv'.")

# Main function to run the analysis
def main():
    print("Log Analysis Started...\n")
    
    # Count requests per IP
    ip_data = count_requests_per_ip(log_file_path)
    
    # Identify the most frequently accessed endpoint
    endpoint_data = most_accessed_endpoint(log_file_path)
    
    # Detect suspicious activity based on login attempts
    suspicious_data = detect_suspicious_activity(log_file_path)
    
    # Save the results to a CSV file
    save_results_to_csv(ip_data, endpoint_data, suspicious_data)
    
    print("\nAnalysis Completed.")

if __name__ == "__main__":
    main()
