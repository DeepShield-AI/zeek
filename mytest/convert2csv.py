import csv
import os

zeek_log_dir = "logs"
zeek_output_dir = "csvs"
# zeek_log_path = "logs/conn.log"      
# csv_output_path = "csvs/conn.csv"  
os.makedirs(zeek_output_dir, exist_ok=True)

for log in os.listdir(zeek_log_dir):
    if log.endswith(".log"):
        zeek_log_path = os.path.join(zeek_log_dir, log)
        csv_output_path = os.path.join(zeek_output_dir, log.replace(".log", ".csv"))
        
    with open(zeek_log_path, 'r') as infile:
        lines = infile.readlines()

    field_line = next(line for line in lines if line.startswith("#fields"))
    fields = field_line.strip().split('\t')[1:]  

    data_lines = [line.strip().split('\t') for line in lines if not line.startswith("#")]

    with open(csv_output_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(fields)
        writer.writerows(data_lines)

print(f"Done")