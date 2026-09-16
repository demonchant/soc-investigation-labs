import re

IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
DOMAIN_PATTERN = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_PATTERN = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")

def classify_input(value):
    value = value.strip()
    if IP_PATTERN.match(value):
        return "ip"
    elif DOMAIN_PATTERN.match(value):
        return "domain"
    elif MD5_PATTERN.match(value) or SHA1_PATTERN.match(value) or SHA256_PATTERN.match(value):
        return "hash"
    else:
        return "unknown"
