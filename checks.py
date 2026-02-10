from config import *

def external_ips_filter(data):
    return [log[1] for log in data if not log[1].startswith(LOCAL_IPs)]
    
def sensitive_ports_filter(data):
    return list(filter(lambda log: log[3] in SENSITIVE_PORT,data))

def big_packets_filter(data):
    return list(filter(lambda log: int(log[5]) >= LARGE_PACKET, data))

def lable_packet_size(data):
    return list(map(lambda log: log + ['LARGE'] if int(log[5]) >= LARGE_PACKET else log + ['NORMAL'] , data))

def count_source_ips(data):
    source_ips = [log[1] for log in data]
    keys = list(set(source_ips))
    values = [source_ips.count(ip) for ip in set(source_ips)]
    return dict(zip(keys, values))

def ports_dict(data):
    return {int(log[3]): log[4] for log in data}

 