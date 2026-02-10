from config import *

def external_ips_filter(data):
    external_ips = []
    for log in data:
        if not log[1].startswith(LOCAL_IPs):
            external_ips.append(log[1])
    return external_ips

