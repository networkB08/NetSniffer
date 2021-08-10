#!/usr/bin/env (python3)
import socket
import struct
import json 

#here we will be declaring some global tabs and spaces
TAB_1 = "\t"
TAB_2 = "\t\t"
TAB_3 = "\t\t\t"
SPACE_1 = " "
SPACE_1 = "  "
SPACE_3 = "   "
#--------------------Layer 2  MAC -Address (Frame) -------------------
# here we are getting the mac address from the ethernet packet 
def get_mac(data):
    dest , src , proto  = struct.unpack('6s6sH',data[0:14])

    return extract_mac(dest) , extract_mac(src) , proto , data[14:] 

# here we are extracting the mac address in a correct format
def extract_mac(pack):
    pack_str = map('{:02x}'.format,pack)
    return ':'.join(pack_str).upper()

#-------------- IP Packet -------------------------
# here we are dealing with the IP packet
def ip_packet(data):
    #firstly we have taken out 1st byte out the IP packet
    vers_length = struct.unpack('B',data[:1])
    vers_length = str(f"{vers_length[0]:08b}") 
    version = int(vers_length[0:4],2)
    length_header = int(vers_length[4:8],2)
    #lets work with the 2nd byte and go further  
    tos , total_length = struct.unpack('!BH',data[1:4])
    #lets work with other information of ip packet 
    ID , flags_offset = struct.unpack('2H',data[4:8])
    flag_offset = str(f"{flags_offset:016b}")
    flag = int(flag_offset[0:3],2)
    offset = int(flag_offset[3:16],2)
    #lets see some of the timeto live and protocol section
    ttl , proto , checksum  = struct.unpack('!B B H',data[8:12])

    return version , length_header , tos , total_length , ID , flag , offset , ttl , proto , checksum , data[12:]

# here  we made a function for checking the information in a packet
def ip_pack_check(proto):
    file = open("protocols.json")
    json_data = json.load(file)
    protocol = "Unassigned Protocol"
    if str(proto) in json_data:
        protocol = json_data["{}".format(proto)]
    return protocol
    
# here we will be getting the ip address of destination and source from ip-packet
def ip_address(data):
    src_address = struct.unpack('4B',data[:4])
    dest_address = struct.unpack('4B',data[4:8])
    options  = struct.unpack('I',data[8:12]) # I = 4bytes options has only one entire block of bytes 
    # lets format the address in correct dotted decimal
    lo = []
    ls = []
    ld = []
    for i in src_address:
        ls.append(str(i))
    for j in dest_address:
        ld.append(str(j))
    for k in options:
        lo.append(str(k))
    src_address = '.'.join(ls)
    dest_address = '.'.join(ld)
    options = '.'.join(lo)
    return src_address , dest_address , options ,data[12:]

# -------------------- TCP-IP  ----------------------
# lets make a function here to unpack TCP-IP segments
def tcp_segment(data):
    src_port  = struct.unpack('H',data[:2])
    dest_port  = struct.unpack('H',data[2:4])
    seq_number = struct.unpack('!i',data[4:8])
    ack_number = struct.unpack('!i',data[8:12])
    head_flags = struct.unpack('H',data[12:14])
    return src_port[0] , dest_port[0] , seq_number[0] , ack_number[0] , head_flags[0] , data[12:]
# here we sll extract flags and head and reserved bits from tcp -segment
def extract_flag(HEAD):
        head = str(f"{HEAD:016b}")
        head_bits = int(head[0:4],2)
        resv_bits = int(head[4:10],2)
        urg_bit = int(head[10:11],2)
        ack_bit = int(head[11:12],2)
        psh_bit = int(head[12:13],2)
        pst_bit = int(head[13:14],2)
        syn_bit = int(head[14:15],2)
        fin_bit = int(head[15:16],2)
        # here only print the data of 4th block of tcp-ip
        print(f"{TAB_2}Head:{head_bits} Resv:{resv_bits}")
        print(f"{TAB_2}URG:{urg_bit}")
        print(f"{TAB_2}ACK:{ack_bit}")
        print(f"{TAB_2}PSH:{psh_bit}")
        print(f"{TAB_2}PST:{pst_bit}")
        print(f"{TAB_2}SYN:{syn_bit}")
        print(f"{TAB_2}FIN:{fin_bit}")
        return 0

# here we have main function of the project ...
def main():
    sock = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3)) # 3 args at a time
    while True:
        raw , addr = sock.recvfrom(65535) # 65535 bytes at a time
        dest , src , proto , data = get_mac(raw)
        #ethernet frame
        print("------------'Packet Starts Here'------------")
        print("[Ethernet Frame]")
        print(f"Destination:{dest} Source:{src} Protocol:{proto}")
        ver , header , tos , length , id_ , flag , offset , ttl , proto , checksum , address_data = ip_packet(data)
        #ip packet TAB 1 (Layer 2 PDU)
        print(f"{TAB_1}[IP Packet]")
        print(f"{TAB_1}Version:{ver} Length of Header:{header} Type of Service:{tos} Length:{length}")
        print(f"{TAB_1}ID:{id_} Flags:{flag} Offset:{offset}")
        print(f"{TAB_1}Time to Live:{ttl} Protocol:{proto} Checksum:{checksum}")
        #some management to the packet according to the protocol TAB 1
        print(f"{TAB_1}Protocol Information:{ip_pack_check(proto)}")
        # ip address here 
        src_add , dest_add , opt , ip_data = ip_address(address_data)
        print(f"{TAB_1}Source IP-Address:{src_add}\n{TAB_1}Destination IP:{dest_add}\n{TAB_1}Options:{opt}")
        #lets come to the TCP-ip segment (Layer 4 PDU) TAB 2
        src_port , dest_port , seq , ack , head , l5_data = tcp_segment(ip_data)
        print(f"{TAB_2}[TCP-IP Segment]")
        print(f"{TAB_2}SRC Port:{src_port} Destination Port:{dest_port}")
        print(f"{TAB_2}Sequence:{seq} Acknowledgement:{ack}")
        extract_flag(head)


main()