from reader import *
from checks import *
from analyzer import *

lines = generate_csv("network_traffic.log") 
suspicious = generate_suspicion_rows(lines)  
count = suspicion_rows_counter(suspicious) 
print(f"Total suspicious: {count}")