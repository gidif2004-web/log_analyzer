from config import *
from reader import load_csv
from pathlib import Path

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

def suspicions_dict(data):
    corrent_dict = {log[1]: [] for log in data }
    external_ips = external_ips_filter(data)
    corrent_dict = {key: (value + ['EXTERNAL_IP'] if key in external_ips and 'EXTERNAL_IP' not in value else value) for key, value in corrent_dict.items()}
    sensitive_ports = list(map(lambda log: log[1], sensitive_ports_filter(data)))
    corrent_dict = {key: (value + ['SENSITIVE_PORT'] if key in sensitive_ports and 'SENSITIVE_PORT' not in value else value) for key, value in corrent_dict.items()}
    big_packets = list(map(lambda log: log[1], big_packets_filter(data)))
    corrent_dict = {key: (value + ['LARGE_PACKET'] if key in big_packets and 'LARGE_PACKET' not in value else value) for key, value in corrent_dict.items()}
    night_activity = list(map(lambda log: log[1], night_activity_filter(data)))
    corrent_dict = {key: (value + ['NIGHT_ACTIVITY'] if key in night_activity and 'NIGHT_ACTIVITY' not in value else value) for key, value in corrent_dict.items()}
    return corrent_dict

def night_activity_filter(data):
    return list(filter(lambda log: log[0][11:].startswith(NIGHT_ACTIVITY),data))

def suspicions_dict_filter(s_dict):
    return dict(filter(lambda val: len(val[1]) >= 2, s_dict.items()))

def hours_list(data):
    return list(map(lambda log: int(log[0][12]) if log[0][11] == '0' else int(log[0][11:13]), data))

def byte_to_kb(data):
    return list(map(lambda log: round(int(log[5])/1024,1),data))
