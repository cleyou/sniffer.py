import struct  # this library will help us to unpack data
import socket

def main():
    host = 'enp0s3'
    print(host)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    s.bind((host, 0))
    p = 0
    while True:
        data = s.recvfrom(65565)  # wait to sniff some ethernet frame
        p += 1
        dataFrame = data[0]

        mac_dst = ":".join([f'{b:02X}' for b in dataFrame[:6]])  # Destination MAC address
        mac_src = ":".join([f'{b:02X}' for b in dataFrame[6:12]])  # Source MAC address
        ethertype = ":".join([f'{b:02X}' for b in dataFrame[12:14]])  # EtherType

        print(f'\nETHERNET FRAME {p:04}\n\t> MAC_DST: {mac_dst} MAC_SRC: {mac_src} ETH_TYP: {ethertype} LENGTH: {len(dataFrame)}')

        if ethertype == '08:00':  # IPv4
            version = dataFrame[14] >> 4
            ip_header_len = ((dataFrame[14] & 15) * 4)
            ttl, protocol, src, dest = struct.unpack('! 8x B B 2x 4s 4s', dataFrame[14:34])

            # decode address in dot-decimal notation to make it human readable
            srcdd = socket.inet_ntoa(src)
            destdd = socket.inet_ntoa(dest)
            print(f'\t>> IPv4 :\n\t\t- Version = {version}, HeaderLength = {ip_header_len}, TTL = {ttl}')
            print(f'\t\t- Protocol = {protocol}, Source = {srcdd}, Dest = {destdd}')

            if protocol == 17:  # UDP
                src_port, dest_port, size = struct.unpack('! H H 2x H', dataFrame[14:22])
                print(f'\t>> UDP : Source Port = {src_port}, Dest Port = {dest_port}, size = {size}')

            elif protocol == 6:  # TCP
                src_port, dest_port, sequence, ackn, orf = struct.unpack('! H H L L H', dataFrame[14:28])
                offset = ((orf >> 12) * 4)
                # flags indicate state of the connection
                flag_urg = ((orf & 32) >> 5)
                flag_ack = ((orf & 16) >> 4)
                flag_psh = ((orf & 8) >> 3)
                flag_rst = ((orf & 4) >> 2)
                flag_syn = ((orf & 2) >> 1)
                print(f'\t>> TCP :\n\t\t- Source Port = {src_port}, Dest Port = {dest_port}')
                print(f'\t\t- Sequence = {sequence}, Acknowledgment={ackn}')
                print(f'\t\t- flags : {flag_urg}/{flag_ack}/{flag_psh}/{flag_rst}/{flag_syn}')
                # divide data array into portion to make it readable
                portion = [dataFrame[offset + i:offset + i + 16] for i in range(0, len(dataFrame[offset:]), 16)]
                # printing
                print(f'\t\t- Data :')
                for portion in portion:
                    print(f'\t\t\t{":".join([f"{b:02X}" for b in portion])}')

                if dest_port == 53:  # DNS
                    dns = ":".join([f'{b:02}' for b in dataFrame[:12]])
                    print(f'\tDNS : {dns}')

            elif protocol == 1:  # ICMP
                # this header is 8 octets but the 4 last are only used for ping
                # so we only unpack the 4 first
                icmp_type, code, checksum, = struct.unpack('! B B H', dataFrame[14:18])
                print(f'\tICMP : Type = {icmp_type}, Code = {code}, Checksum = {checksum}')


        elif ethertype == '86:DD':  # IPv6
            ipv6_header = dataFrame[14:54]  #
            src_ipv6, dest_ipv6 = struct.unpack('! 16s 16s', ipv6_header[8:40])  # Unpack source and destination IPv6 addresses
            src_ipv6 = ":".join([f'{b:02X}' for b in src_ipv6])
            dest_ipv6 = ":".join([f'{b:02X}' for b in dest_ipv6])
            print(f'\t>>IPv6: {ipv6_header}')
            print(f'\t\t- Source IPv6 : {src_ipv6}, Dest IPv6 : {dest_ipv6}')
            next_header = dataFrame[20]  # Next Header field in IPv6 header

            if next_header == 58:  # ICMPv6
                icmpv6_header = dataFrame[54:58]  # 14 (ET_head) + 40 (ICMPv6)
                icmpv6_type, icmpv6_code, icmpv6_checksum = struct.unpack('! B B H', icmpv6_header)
                print(f'\tICMPv6:')
                print(f'\t\t- Type = {icmpv6_type}, Code = {icmpv6_code}, Checksum = {icmpv6_checksum}')

            elif next_header == 6:  # TCP ipv6
                src_port, dest_port, sequence, ackn, orf = struct.unpack('! H H L L H', dataFrame[54:68])
                offset = ((orf >> 12) * 4)
                flag_urg = ((orf & 32) >> 5)
                flag_ack = ((orf & 16) >> 4)
                flag_psh = ((orf & 8) >> 3)
                flag_rst = ((orf & 4) >> 2)
                flag_syn = ((orf & 2) >> 1)
                print(f'\t>> TCP :\n\t\t- Source Port = {src_port}, Dest Port = {dest_port}')
                print(f'\t\t- Sequence = {sequence}, Acknowledgment={ackn}')
                print(f'\t\t- flags : {flag_urg}/{flag_ack}/{flag_psh}/{flag_rst}/{flag_syn}')
                # divide data array into portion to make it readable
                portion = [dataFrame[offset + i:offset + i + 16] for i in range(0, len(dataFrame[offset:]), 16)]
                # printing
                print(f'\t\t- Data :')
                for portion in portion:
                    print(f'\t\t\t{":".join([f"{b:02X}" for b in portion])}')

            elif next_header == 17:  # UDP
                udp_header = dataFrame[54:62] # remind : 14 (ethernet header) + 40 (IPv6)
                src_port, dest_port, length, checksum = struct.unpack('! H H H H', udp_header)
                print(f'\t>> UDP : Source Port = {src_port}, Dest Port = {dest_port}, Length = {length}, Checksum = {checksum}')

                if dest_port == 53:  # DNS
                    dns_data = dataFrame[62:74]
                    dns = ":".join([f'{b:02X}' for b in dns_data])
                    print(f'DNS: {dns}')

        elif ethertype == '08:06':  # ARP
            arp_header = dataFrame[14:42]
            hardware_type, protocol_type, hardware_size, protocol_size, opcode = struct.unpack('! H H B B H', arp_header[:8])
            sender_mac = ":".join([f'{b:02X}' for b in arp_header[8:14]])  # Sender MAC address
            sender_ip = socket.inet_ntoa(arp_header[14:18])  # Sender IP address
            dest_mac = ":".join([f'{b:02X}' for b in arp_header[18:24]])  # Target MAC address
            dest_ip = socket.inet_ntoa(arp_header[24:28])  # Target IP address
            print(f'\t>> ARP: Hardware Type = {hardware_type}, Protocol Type = {protocol_type}')
            print(f'\t\t- Hardware Size = {hardware_size}, Protocol Size = {protocol_size}, Opcode = {opcode}')
            print(f'\t\t- Sender MAC = {sender_mac}, Sender IP = {sender_ip}')
            print(f'\t\t- Target MAC = {dest_mac}, Target IP = {dest_ip}')

# this condition is a popular way to execute a script
if __name__ == '__main__':
    main()
