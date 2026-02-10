from config import *

def external_ips_filter(data):
    return [log[1] for log in data if not log[1].startswith(LOCAL_IPs)]
    
def sensitive_ports_filter(data):
    return list(filter(lambda log: log[3] in SENSITIVE_PORT,data))

def big_packets_filter(data):
    return list(filter(lambda log: int(log[5]) >= LARGE_PACKET, data))

def lable_packet_size(data):
    return list(map(lambda log: log + ['LARGE'] if int(log[5]) >= LARGE_PACKET else log + ['NORMAL'] , data))

print (lable_packet_size([[1,2,5,2,2,'5436'],[1,2,2,2,2,'4436'],[1,2,2,2,2,'6436'],[1,2,2,2,2,'436']]))