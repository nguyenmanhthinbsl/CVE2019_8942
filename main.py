import pyshark, csv, sys, os, binascii, hashlib, argparse
from datetime import datetime
import subprocess
import os
import logging
import array
from pathlib import Path
import socket
import tqdm

def get_http_payload(packet):
    if 'tcp' in packet:
        if 'tcp.payload' in packet.tcp._all_fields:
            a=str(packet.tcp.payload)
            tcpPayload = a.replace(':','')
            data = bytes.fromhex(tcpPayload)
            return data.decode('utf-8', 'replace').encode('cp850','replace').decode('cp850')\
                .replace('\n','').replace('\t','')\
                .replace('\r','').replace('\\x', '')\
                .replace(',', '|')
    return ''

def get_packet_details(packet):
    try:
        protocol = packet.highest_layer
        source_address = packet.ip.src
        source_port = packet[packet.transport_layer].srcport
        destination_address = packet.ip.dst
        destination_port = packet[packet.transport_layer].dstport
        packet_time = packet.sniff_time
        packet_data = str(get_http_payload(packet))
        f = open('traffic.csv', 'a')
        writer = csv.writer(f, delimiter=',',lineterminator='\n')
        row = [protocol, source_address, source_port, destination_address, destination_port, packet_time, packet_data]
        writer.writerow(row)
        return {
            "protocol":protocol, 
            "source_address":source_address, 
            "source_port":source_port, 
            "destination_address":destination_address, 
            "destination_port":destination_port, 
            "packet_time":packet_time, 
            "packet_data":packet_data
        }
    except Exception:
        print(Exception)

def capture_live_packets(network_interface):
    capture = pyshark.LiveCapture(interface=network_interface)
    for raw_packet in capture.sniff_continuously():
        if "HTTP" in raw_packet:
            p = get_packet_details(raw_packet)
            if is_attack_packet(p):
                current_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                warnning_msg = current_timestamp +" [Warning: Found malicious traffic signature based detection CVE 2019-8942] from IP:"+p['source_address']+" to IP:"+p['destination_address']
                logging.warning(warnning_msg)
                with open('log.txt', 'a') as logfile:
                    logfile.write(warnning_msg)
                    logfile.write("\n")

def is_attack_packet(packet):
    if packet['packet_data'] is None:
        return False
    data = str(packet['packet_data'])
    # if "0x6d6574615f696e7075745b5f77705f61747461636865645f66696c655d"  in data:
    # if "8&meta_input%5b_wp_attached_file%5d=" in data:
    if "8&meta_input%5b_wp_" in data:
        return True
    return False

def main():
    parser = argparse.ArgumentParser(description='Capture live network packets.')
    parser.add_argument('-i', '--interface', dest='network_interface', required=True, help='Network interface to capture packets from')
# parser.add_argument('-o', '--output', dest='traffic_file', required=True, help='Output traffic file (e.g., traffic_file.csv)')
    # parser.add_argument('-l', '--logfile', dest='logfile', required=True, help='Log file (e.g., logfile.txt)')

    args = parser.parse_args()

    try:
        # capture_live_packets(args.network_interface, args.traffic_file, args.logfile)
        capture_live_packets(args.network_interface)
    except Exception as e:
        print(e)

if __name__ == "__main__":
    print("""
                 _                           _          _        _                _    _                         
                | |                         | |        | |      | |              | |  (_)                        
    _ __    ___ | |_ __      __  ___   _ __ | | __   __| |  ___ | |_   ___   ___ | |_  _  _ __    __ _           
    | '_ \  / _ \| __|\ \ /\ / / / _ \ | '__|| |/ /  / _` | / _ \| __| / _ \ / __|| __|| || '_ \  / _` |          
    | | | ||  __/| |_  \ V  V / | (_) || |   |   <  | (_| ||  __/| |_ |  __/| (__ | |_ | || | | || (_| | _  _  _  
    |_| |_| \___| \__|  \_/\_/   \___/ |_|   |_|\_\  \__,_| \___| \__| \___| \___| \__||_||_| |_| \__, |(_)(_)(_) 
                                                                                                __/ |          
                                                                                                |___/           
    """)

    main()
