#!/usr/bin/python
#Author: Akash Sharma

import socket
import struct
import textwrap
import argparse, sys
import binascii
import threading
from threading import Thread
import time
import collections 
import logging
from logHelper import setup_logger


list_new = []
#For the purpose of tracking packets across a period of time
queue_tracker = set()

#queue
RSA_Validation_Queue = collections.deque()
Cyclic_Validation_Queue = collections.deque()
RSA_Error_Log_Queue = collections.deque()
Cyclic_Error_Log_Queue = collections.deque()
udp_checksum_Queue = collections.deque()

check = threading.Condition()

# first file logger
logger = setup_logger('HASH_MISMATCH', 'verification_failures.log')
# second file logger
super_logger = setup_logger('CYCLIC_MISMATCH', 'checksum_failures.log')

#Thread
def RSA_validation():
    while True:
        while RSA_Validation_Queue:
            removedElem_RSA = RSA_Validation_Queue.pop()
            packet_digital_sig_str = removedElem_RSA[2];
            packet_squence_number_str = removedElem_RSA[1];

            if packet_digital_sig_str == packet_squence_number_str:
                print("Hash matched")
            else:
                hex_packet_id_str = removedElem_RSA[0] + " (Packet ID - in hex)"
                packet_squence_number_str = str(removedElem_RSA[1]) + " (Packet sequence number)"
                packet_digital_sig_str = str(removedElem_RSA[2]) + " (received hash)"
                stored_digital_sig_str = str(removedElem_RSA[3]) + " (expected hash)"
      
                RSA_Error_Log_Queue.append([hex_packet_id_str,packet_squence_number_str,packet_digital_sig_str,stored_digital_sig_str])
#Thread
def Cyclic_validation():
    while True:
        while Cyclic_Validation_Queue:
            removedElem_Cyclic= Cyclic_Validation_Queue.pop()
            recieved_slice = str(removedElem_Cyclic[3])
            expected_crc32 = (removedElem_Cyclic[4]) 
            hex_packet_id_str = removedElem_Cyclic[0]
            checksum_number_str = str(removedElem_Cyclic[2])
     
            constructed_crc32 = (removedElem_Cyclic[3])
    
            func_return = concat_crc32(key, checksum_number_str,(removedElem_Cyclic[3]),str(removedElem_Cyclic[0]))
            if func_return:
                print(func_return)
 
            if hex_packet_id_str not in queue_tracker:
                queue_tracker.add(hex_packet_id_str)
                #a set that only allows one instance of the packet to remain in the queue(unique)
                Cyclic_Validation_Queue.append([removedElem_Cyclic[0],removedElem_Cyclic[1],'null',removedElem_Cyclic[3],removedElem_Cyclic[4]])
        
            if binascii.crc32(constructed_crc32) == expected_crc32 or constructed_crc32 == expected_crc32:
 #               print("crc32 matched")
                queue_tracker.remove(hex_packet_id_str)
            
            else: 
                hex_packet_id_str = str(removedElem_Cyclic[0]) + " (Packet ID - in hex)"
                packet_squence_number_str = str(removedElem_Cyclic[1]) + " (Packet sequence number)" 
                checksum_number_str = str(removedElem_Cyclic[2]) + " (Cyclic checksum iteration)"
                constructed_crc32 = str(binascii.crc32(constructed_crc32)) + " (received crc32)"
                #What is the expected crc32?
                Cyclic_Error_Log_Queue.append([hex_packet_id_str,packet_squence_number_str,checksum_number_str,constructed_crc32,expected_crc32])

#delay, the arguement passed
#Thread               
def log_rsa_error():
    while True:
        time.sleep(delay)
        while RSA_Error_Log_Queue:     
            removedElem_RSA = RSA_Error_Log_Queue.pop() 
            for x in (removedElem_RSA):
                logger.error(x)     
            logger.error('\n')
#Thread
def log_cyclic_error():
    while True:
        time.sleep(delay)
        while Cyclic_Error_Log_Queue:
            removedElem_Cyclic= Cyclic_Error_Log_Queue.pop()
            for x in (removedElem_Cyclic):
                super_logger.error(x)
            super_logger.error('\n')

#store rsa number
def verify_digital_sig(location):
    file_digital_sig = open(location, "rb").read()
    return binascii.hexlify(file_digital_sig)

#The files that are passed have their packets read and stored
def verify_cyclic_checksum(location):
    cyclic_checksum_jpg = open(location, "rb").read()
    return cyclic_checksum_jpg

#arguements
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--keys", help="a dictionary of {packet_id: key_file_path} mappings", required=True)
    parser.add_argument("--binaries", help="a dictionary of {packet_id: binary_path} mappings", required=True)
    parser.add_argument("-p", help="port, to receive packets on", required=True)
    parser.add_argument("-d", help="delay, (in seconds) for writing to log files", required=True)


    args = parser.parse_args()
    
    keys_mapping=eval(str(args.keys))
    binaries_mapping=eval(str(args.binaries))
    
    binary_crc32={}
    set_packet_binary={} #sequence number
    set_packet_keys={} #store sequence number to rsa key
    
    UDP_PORT=int(args.p)
    delay=int(args.d)  
 
    
    def getList(dict): 
        return dict.keys_mapping() 
    
    id_packet =(keys_mapping)
        #key is packet_id
    for key in list(id_packet.keys()):

        key_file=str(keys_mapping.get(key))
        binary_file=str(binaries_mapping.get(key)) 
        keys_mapping[key]=verify_digital_sig(key_file)
        
        #parse file and store whatever about the file
        binaries_mapping[key] = verify_cyclic_checksum(binary_file)
        binary_crc32[key]=binascii.crc32(binaries_mapping[key])
        
        set_packet_binary[key] = set()
        set_packet_keys[key] = set()
        key={}
       
        
    
#Thread
def main(): 
    conn =  socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
   
   #facing many exceptions
        try:
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            (version, header_length, ttl, proto, src, target, data) =  ipv4_packet(data)
            src_port, dest_port, length, checksum_udp_segment, data = udp_segment(data)
            data_udp_checksum = data 
            packet_id, packet_seq, repeating_xor, checksums, data = custom_packet(data)
            dword,data = custom_packet_dword(data)
           
        except:
             #print("An exception occurred")
         if eth_proto == 8: 
            if proto == 17:
                if dest_port == UDP_PORT:
               #    print(str(src_port_hex) + "src")
               #    print(str(dest_port_hex) + "dst")
               #    print(str(size_hex) +"length")
               #    print(str(checksum_udp_segment_hex)+"check")
               #    print('Packet Id: {}, Packet Sequence: {}, Repeating Xor: {}, CheckSums: {}'.format(hex(packet_id), packet_seq, repeating_xor, checksums)) 
                   custom_packet_dword(data,hex(packet_id),packet_seq,checksums)
                   custom_packet_rsa(data, hex(packet_id),packet_seq)
                   udp_checksum_Queue.append([src, target, length, checksum_udp_segment, data_udp_checksum, src_port,dest_port])
                  
#parsing        
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:] 

def get_mac_addr(bytes_addr):
    bytes_str = map('{:20x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])  
    return version, header_length, ttl , proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def udp_segment(data):
    src_port, dest_port, size,checksum_udp_segment = struct.unpack('! H H H H', data[:8])
    return src_port, dest_port, size, checksum_udp_segment, data[8:]
#parsing 

#converting ip address to 16 bit portion, for initial checksum check(verify packet structual integrity)
def bit_ipaddress_convert(ip_address):
    ip_address=str(binascii.hexlify(socket.inet_aton((ip_address))))    
    first_seg=ip_address[2:6]
    second_seg=ip_address[6:10]
    hex_first_seg = from_hex(first_seg)
    hex_second_seg = from_hex(second_seg)
    return hex_first_seg,hex_second_seg

#the initial check(DOESN'T WORK)
def udp_checksum_check():
    while True:
        while udp_checksum_Queue:  
            removedElem_udp= udp_checksum_Queue.pop()
           
            src =removedElem_udp[0]
            target =removedElem_udp[1]
            size =removedElem_udp[2]
            checksum_udp_segment =removedElem_udp[3] 
            data_udp_checksum = removedElem_udp[4]
            src_port=(removedElem_udp[5])
            dst_port=(removedElem_udp[6])
           
            word=[hex(data_udp_checksum[i]*16**2 + data_udp_checksum[i+1]) for i in range(0,len(data_udp_checksum),2)]
           #the data portion, over 100 bytes in some cases, and, supposedly, the way to convert it to 16 bit portions
            sum=0
            for h in word: 
                x = from_hex(h)
                sum = sum +x 

            src_ip_hex_seg1,src_ip_hex_seg2 = bit_ipaddress_convert(src)
            dest_ip_hex_seg1,dest_ip_hex_seg2 = bit_ipaddress_convert(target) 
            protocol_hex =17
          #  checksum_udp_segment_hex = hex(checksum_udp_segment)
           
            #psuedo header additions and more, for purposes of computing a checksum check
            sum_phdr= sum + src_ip_hex_seg1 + src_ip_hex_seg2 + src_port + dst_port+ dest_ip_hex_seg1 + 10 + dest_ip_hex_seg2 + size + protocol_hex 
          
           #calls method to adjust overflow, if any
            number = adjust_hex(from_hex(hex(sum_phdr)),from_hex('0xFFFF'))
            
            #print(hex(number), hex(checksum_udp_segment))
         #   print((number) == (checksum_udp_segment))
            #is the way I calculated correct? check. Unforunately,no.

#return int from string of hex
def from_hex(hexdigits):
    return int(hexdigits, 16)

#if hex overflows in the 0xXXXX part
def adjust_hex(sum_phdr,greatestNumb):
    while sum_phdr > greatestNumb:
        hex_string= hex(sum_phdr)
        #print(hex_string)
        hex_without_x=hex_string[2:len(hex_string)]
       # print(sum_phdr)
        if not len(hex_without_x) == 8:
            numb_pad_zero = 8 - len(hex_without_x)
            x = 0
            while x != numb_pad_zero:
                hex_without_x = "0" + hex_without_x
                x = x +1
            seg_1=hex_without_x[0:4]
            seg_2=hex_without_x[4:8]
            
            sum_phdr = from_hex(seg_1)+from_hex(seg_2)
            
    result = sum_phdr ^ greatestNumb 
    return (result)
  
#parsing of custom packet
def custom_packet(data): 
    packet_id, packet_seq, repeating_xor, checksums = struct.unpack('! I L H H', data[:12]) 
    return packet_id, packet_seq,repeating_xor, checksums,data[12:]

#parsing custom packet, the crc part
def custom_packet_dword(data,hex_packet_id,packet_squence_number,checksum_number):
    length=len(data)
    splice=data[12:length-64]
    myset=set_packet_binary.get(hex_packet_id)

    if packet_squence_number not in myset: 
        myset.add(packet_squence_number)    
        Cyclic_Validation_Queue.append([hex_packet_id, packet_squence_number, checksum_number, splice, binary_crc32[hex_packet_id]]) 

#rsa validation
def custom_packet_rsa(data, hex_packet_id,packet_squence_number): 
    length=len(data) 
    spl=data[length-67:length]
    packet_digital_sig=binascii.hexlify(spl)
     
    myset=set_packet_keys.get(hex_packet_id)
    if packet_squence_number not in myset:
        myset.add(packet_squence_number)
        stored_digital_sig = str(keys_mapping.get(hex_packet_id))
        RSA_Validation_Queue.append([hex_packet_id,packet_squence_number,packet_digital_sig,stored_digital_sig])        

#My way of solving unordered packets(but numbered) over any period of time
def concat_crc32(dict_crc, checksum_num, byte,hex_packet_id):
    if not byte == 'null':
        myset=set_packet_binary.get(hex_packet_id) 
        dict_crc[checksum_num]=byte
        index = 0
        byte_string= ''
        for index in dict_crc.keys():
            if(checkKey(dict_crc, index)):
                index = index + 1
                byte_string=byte_string+dict_crc.get(index)
            else: 
                return False
        return byte_string

#Self-Explanatory(S-E)
def checkKey(dict, key):  
    if key in dict.keys(): 
       return False  
    else: 
       return True 
  
#Thread Initiator
if __name__ == '__main__':
    Thread(target = main).start()
    Thread(target = log_rsa_error).start()
    Thread(target = log_cyclic_error).start()
    Thread(target = Cyclic_validation).start()
    Thread(target = RSA_validation).start()
    Thread(target = udp_checksum_check).start()
