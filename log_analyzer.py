
import re
from collections import defaultdict

LOG_FILE_PATH = "sample_logs/auth.log"

FAILED_LOGIN_REGEX = re.compile(
    r"(?P<date>\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) .* Failed password for (invalid user )?(?P<user>\w+) from (?P<ip>[\d.]+) port"
)

def read_and_find_failed_logins(filepath):
    with open(filepath, 'r') as file:
        for line in file:
            if "Failed password" in line:
                match = FAILED_LOGIN_REGEX.search(line)
                if match:
                    # reading the date, user, and IP address from the matched line
                    date = match.group("date")
                    user = match.group("user")
                    ip = match.group("ip")
                    print(f"[{date}] Failed login for user '{user}' from IP: {ip}")

                    # If regex does not match, just print the line

def count_failed_attempts(filepath, threshold=5):
    failed_attempts = defaultdict(int)

    with open(filepath, 'r') as file:
        for line in file:
            if "Failed password" in line:
                match = FAILED_LOGIN_REGEX.search(line)
                if match:
                    ip = match.group("ip")
                    failed_attempts[ip] += 1

    print("\n--- Flagged IPs (Too Many Failed Attempts) ---")
    for ip, count in failed_attempts.items():
        if count >= threshold:
            print(f"{ip}: {count} failed attempts")


if __name__ == "__main__":
    read_and_find_failed_logins(LOG_FILE_PATH)
    count_failed_attempts(LOG_FILE_PATH)
    # This will print all lines with "Failed password" from the log file
    # You can redirect the output to a file or process it further as needed

