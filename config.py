LOCAL_IPs = ('10.', '192.168.')
SENSITIVE_PORT = ('22', '23', '3389')
LARGE_PACKET = 5000
NIGHT_ACTIVITY = ('00', '01', '02', '03', '04', '05', '06:00:00')
suspicion_checks = { "EXTERNAL_IP": lambda row: not row[1].startswith(LOCAL_IPs),
"SENSITIVE_PORT": lambda row: row[3] in SENSITIVE_PORT,
"LARGE_PACKET": lambda row: int(row[5]) >= LARGE_PACKET,
"NIGHT_ACTIVITY": lambda row: row[0][11:].startswith(NIGHT_ACTIVITY) }