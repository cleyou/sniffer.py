import struct
import socket
import logging

def main():
    host = 'enp0s3'
    print(host)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    s.bind((host, 0))
    p = 0

    # Configure logging without timestamps
    logging.basicConfig(filename='sniffer.log', level=logging.INFO,
                        format='%(message)s')
    logger = logging.getLogger()

    while True:
        data = s.recvfrom(65565)
        p += 1
        dataFrame = data[0]
        mac_dst = ":".join([f'{b:02X}' for b in dataFrame[:6]])  # Destination MAC address
        mac_src = ":".join([f'{b:02X}' for b in dataFrame[6:12]])  # Source MAC address
        ethertype = ":".join([f'{b:02X}' for b in dataFrame[12:14]])  # EtherType

        logger.info(f'{p:03}\n\t> MAC_DST: {mac_dst} MAC_SRC: {mac_src} ETH_TYP: {ethertype} LENGTH: {len(dataFrame)}')

        if ethertype == '08:00':  # IPv4
            version = dataFrame[14] >> 4
            ip_header_len = ((dataFrame[14] & 15) * 4)
            ttl, protocol, src, dest = struct.unpack('8xBB2x4s4s', dataFrame[14:34])
            srcdd = socket.inet_ntoa(src)
            destdd = socket.inet_ntoa(dest)
            logger.info(f'\t>> IPv4 header :\n\t\t- IPversion = {version}, HeaderLength = {ip_header_len}, TTL = {ttl}')
            logger.info(f'\t\t- Protocol = {protocol}, Source = {srcdd}, Dest = {destdd}')

            if protocol == 17:  # UDP
                src_port, dest_port, size = struct.unpack('! H H 2x H', dataFrame[34:42])
                logger.info(f'\t>> UDP : Source Port = {src_port}, Dest Port = {dest_port}, size = {size}')
                if src_port == 53 or dest_port == 53:  # DNS
                    dns_header = dataFrame[42:54]
                    transaction_id, flags, questions, answers, authority, additional = struct.unpack('!HHHHHH', dns_header)
                    logger.info(f'\t>>> DNS Records :')
                    logger.info(f"\t\t- ID: {transaction_id}")
                    logger.info(f"\t\t- flags: {flags} (Binary: {flags:016b})")
                    logger.info(f"\t\t- Number of questions: {questions}")
                    logger.info(f"\t\t- Number of answers: {answers}")
                    logger.info(f"\t\t- Number of authority records: {authority}")
                    logger.info(f"\t\t- Number of additional records: {additional}")

            if protocol == 6:  # TCP
                tcp_header = dataFrame[34:48]
                src_port, dest_port, sequence, ackn, orf = struct.unpack('!HHIIH', tcp_header)
                offset = ((orf >> 12) * 4)
                flag_urg = ((orf & 32) >> 5)
                flag_ack = ((orf & 16) >> 4)
                flag_psh = ((orf & 8) >> 3)
                flag_rst = ((orf & 4) >> 2)
                flag_syn = ((orf & 2) >> 1)
                logger.info(f'\t>>> TCP :\n\t\t- Source Port = {src_port}, Dest Port = {dest_port}')
                logger.info(f'\t\t- Sequence = {sequence}, Acknowledgment = {ackn}')
                logger.info(f'\t\t- flags : {flag_urg}/{flag_ack}/{flag_psh}/{flag_rst}/{flag_syn}')
                if src_port == 53 or dest_port == 53:  # DNS over TCP
                    length = struct.unpack('!H', dataFrame[48:50])[0]
                    dns_data = dataFrame[50:50 + length]
                    transaction_id, flags, questions, answers, authority, additional = struct.unpack('!HHHHHH', dns_data[:12])
                    logger.info(f"\t>>> DNS Records (TCP):")
                    logger.info(f"\t\t- Transaction ID: {transaction_id}")
                    logger.info(f"\t\t- Flags: {flags} (Binary: {flags:016b})")
                    logger.info(f"\t\t- Number of Questions: {questions}")
                    logger.info(f"\t\t- Number of Answers: {answers}")
                    logger.info(f"\t\t- Number of Authority Records: {authority}")
                    logger.info(f"\t\t- Number of Additional Records: {additional}")

            elif protocol == 1:  # ICMP
                icmp_type, code, checksum = struct.unpack('! B B H', dataFrame[34:38])
                logger.info(f'\tICMP : Type = {icmp_type}, Code = {code}, Checksum = {checksum}')

        elif ethertype == '86:DD':  # IPv6
            ipv6_header = dataFrame[14:54]  # ipv6 header = 40 octets
            src_v6, dest_v6 = struct.unpack('16s 16s', ipv6_header[8:40])
            srcdd_v6 = socket.inet_ntop(socket.AF_INET6, src_v6)
            destdd_v6 = socket.inet_ntop(socket.AF_INET6, dest_v6)
            logger.info(f'\t>> IPv6: ')
            logger.info(f'\t\t- Source IPv6 : {srcdd_v6}\n\t\t- Dest IPv6 : {destdd_v6}')

        elif ethertype == '08:06':  # ARP
            arp_header = dataFrame[14:42]
            hardware_type, protocol_type, hardware_size, protocol_size, opcode = struct.unpack('! H H B B H', arp_header[:8])
            if hardware_type == 1:  # the ethernet code, here we should mostly have this type
                hardware_type = 'Ethernet'
            if protocol_type == 2048:  # the only protocol we will uncode here
                protocol_type = 'IPv4'
            if opcode == 1:  # request
                opcode = f'request ({opcode})'
            elif opcode == 2:  # reply
                opcode = f'reply({opcode})'
            sender_mac = ":".join([f'{b:02X}' for b in arp_header[8:14]])  # Sender MAC address
            sender_ip = socket.inet_ntoa(arp_header[14:18])  # Sender IP address
            dest_mac = ":".join([f'{b:02X}' for b in arp_header[18:24]])  # Target MAC address
            dest_ip = socket.inet_ntoa(arp_header[24:28]])  # Target IP address
            logger.info(f'\t>> ARP:\n\t\t- Hardware Type = {hardware_type}, Protocol Type = {protocol_type}')
            logger.info(f'\t\t- Hardware Size = {hardware_size}, Protocol Length = {protocol_size}, Opcode = {opcode}')
            logger.info(f'\t\t- Sender MAC = {sender_mac}, Sender IP = {sender_ip}')
            logger.info(f'\t\t- Target MAC = {dest_mac}, Target IP = {dest_ip}')

        logger.info('\n')

if __name__ == '__main__':
    main()










