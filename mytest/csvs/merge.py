import pandas as pd
import os
import argparse
import warnings

warnings.filterwarnings("ignore")

def load_data(file_path):
    """Load CSV file and replace '-' with NaN"""
    if not os.path.exists(file_path):
        print(f"File does not exist: {file_path}")
        return pd.DataFrame()
    
    try:
        df = pd.read_csv(file_path)
        df = df.replace('-', float('nan'))  
        return df
    except Exception as e:
        print(f"Error loading file {file_path}: {e}")
        return pd.DataFrame()

def merge_protocol_data(conn_df, protocol_df, on_columns):
    """Merge protocol-related data and fill NaN with -1"""
    if conn_df.empty or protocol_df.empty:
        return conn_df
    
    print(len(conn_df), len(protocol_df))
    merged_df = pd.merge(conn_df, protocol_df, how='left', on=on_columns)
    merged_df = merged_df.fillna(-1)
    return merged_df

def process_service_column(df):
    """Process service column by filling NaN with -1"""
    df['service'] = df['service'].fillna(-1)
    return df

def save_to_csv(df, file_path):
    """Save DataFrame to CSV file"""
    try:
        df.to_csv(file_path, index=False)
        print(f"File saved: {file_path}")
    except Exception as e:
        print(f"Error saving file {file_path}: {e}")

def main():
    parser = argparse.ArgumentParser(description='Merge network traffic log files')
    parser.add_argument('--input_dir', default='.', help='Input file directory')
    parser.add_argument('--output_dir', default='.', help='Output file directory')
    args = parser.parse_args()
    
    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)
    
    conn_path = os.path.join(args.input_dir, 'conn.csv')
    conn_df = load_data(conn_path)
    
    if conn_df.empty:
        print("No valid connection data, program exited")
        return
    
    tcp_conn = conn_df[conn_df['proto'] == 'tcp'].copy()
    udp_conn = conn_df[conn_df['proto'] == 'udp'].copy()
    
    print(f"Number of TCP connections: {len(tcp_conn)}")
    print(f"Number of UDP connections: {len(udp_conn)}")
    
    # HTTP data
    http_path = os.path.join(args.input_dir, 'http.csv')
    http_df = load_data(http_path)
    
    # SSL data
    ssl_path = os.path.join(args.input_dir, 'ssl.csv')
    ssl_df = load_data(ssl_path)

    # DNS data
    dns_path = os.path.join(args.input_dir, 'dns.csv')
    dns_df = load_data(dns_path)

    # Common merge columns
    common_columns = ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p']
    
    # Extended features data
    extendted_path = os.path.join(args.input_dir, 'extended_features.csv')
    extended_df = load_data(extendted_path)

    if not extended_df.empty:
        tcp_conn = merge_protocol_data(tcp_conn, extended_df, common_columns)
        udp_conn = merge_protocol_data(udp_conn, extended_df, common_columns)

    if not http_df.empty:
        tcp_conn = merge_protocol_data(tcp_conn, http_df, common_columns)
    
    if not ssl_df.empty:
        tcp_conn = merge_protocol_data(tcp_conn, ssl_df, common_columns)

    if not dns_df.empty:
        udp_conn = merge_protocol_data(udp_conn, dns_df, common_columns)
    
    tcp_output_path = os.path.join(args.output_dir, 'tcp.csv')
    udp_output_path = os.path.join(args.output_dir, 'udp.csv')
    
    save_to_csv(tcp_conn, tcp_output_path)
    save_to_csv(udp_conn, udp_output_path)
    
    print("Processing completed")

if __name__ == "__main__":
    main()    