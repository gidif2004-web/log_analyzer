from config import *
from checks import *

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

def suspicions_dict_filter(s_dict):
    return dict(filter(lambda val: len(val[1]) >= 2, s_dict.items()))

def all_suspicions_in_row(row):
    return list(dict(filter(lambda item: item[1](row) , suspicion_checks.items())).keys())

def all_log_by_suspicion_checks(data):
    return list(filter(lambda row: len(row) >= 1 ,map(lambda row: all_suspicions_in_row(row), data)))

def generate_suspicion_rows(rows_generator):
    for row in rows_generator:
        if len(all_suspicions_in_row(row)) >= 1:
            yield row

def generate_suspicion_rows_with_details(rows_generator):
    for row in rows_generator:
        if len(all_suspicions_in_row(row)) >= 1:
            yield (row, all_suspicions_in_row(row))

def suspicion_rows_counter(rows_generator):
    return sum(1 for row in rows_generator if len(all_suspicions_in_row(row)) >= 1)
