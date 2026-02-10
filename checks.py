from config import *

def external_ips_filter(data):
    return [log[1] for log in data if not log[1].startswith(LOCAL_IPs)]
    
def sensitive_ports_filter(data):
    return list(filter(lambda log: log[3] in SENSITIVE_PORT,data))

