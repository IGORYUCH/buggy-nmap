def ip_to_hex(ip: str) -> bytes:
    octets = []
    for octet in ip.split('.'):
        octets.append(bytes.fromhex(hex(int(octet))[2:].zfill(2)))
    return b''.join(octets)


def hex_to_ip(hexip: bytes) -> str:
    octets = []
    for octet in hexip:
        octets.append(str(octet))
    return '.'.join(octets)


def get_start_end(ip):
    octets = ip.split('.')
    start_ip_octets = []
    end_ip_octets = []
    for octet in octets:
        if '-' in octet:
            start, end = octet.split('-')
            start_ip_octets.append(start)
            end_ip_octets.append(end)
        else:
            start_ip_octets.append(octet)
            end_ip_octets.append(octet)
    return '.'.join(start_ip_octets), '.'.join(end_ip_octets)

