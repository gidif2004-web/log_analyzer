import csv

def load_csv(path):
    with open(path, 'r', newline = '', encoding = 'utf-8') as file:
        reader = csv.reader(file)
        return list(reader)
        
def generate_csv(path):
    with open(path, 'r', newline = '', encoding = 'utf-8') as file:
        reader = csv.reader(file)
        for row in reader:
            yield row
