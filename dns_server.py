import socket
import struct
import threading

ROOT = ['198.41.0.4']


def encode_domain(name):
    parts = name.encode().split(b'.')
    result = b''
    for p in parts:
        if p:
            result += len(p).to_bytes(1) + p
    return result + b'\x00'


def decode_domain(data, offset):
    parts, orig = [], None
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return '.'.join(parts), (orig or offset + 1)
        if (length & 0xC0) == 0xC0:
            ptr = struct.unpack('!H', data[offset: offset + 2])[0] & 0x3FFF
            orig = orig or offset + 2
            offset = ptr
            continue
        offset += 1
        parts.append(data[offset: offset + length].decode('utf-8', 'ignore'))
        offset += length
    return '.'.join(parts), orig or offset


def parse_response(resp):
    _, _, qd, an, ns, ar = struct.unpack('!HHHHHH', resp[:12])
    offset = 12
    for _ in range(qd):
        _, offset = decode_domain(resp, offset)
        offset += 4

    ans_start = offset
    for _ in range(an):
        _, offset = decode_domain(resp, offset)
        offset += 10 + struct.unpack('!H', resp[offset + 8: offset + 10])[0]
    ans_end = offset

    ns_recs = []
    for _ in range(ns):
        _, offset = decode_domain(resp, offset)
        rtype, _, _, rdlen = struct.unpack('!HHIH', resp[offset: offset + 10])
        offset += 10
        if rtype == 2:
            ns_recs.append(decode_domain(resp, offset)[0])
        offset += rdlen

    glue = {}
    for _ in range(ar):
        name, offset = decode_domain(resp, offset)
        rtype, _, _, rdlen = struct.unpack('!HHIH', resp[offset: offset + 10])
        offset += 10
        if rtype == 1 and rdlen == 4:
            glue[name.lower()] = socket.inet_ntoa(resp[offset: offset + 4])
        offset += rdlen

    return resp[ans_start:ans_end], an, ns_recs, glue


def resolve(query):
    servers = ROOT
    for _ in range(5):
        next_s = []
        for ip in servers:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2)
                    s.connect((ip, 53))
                    s.sendall(struct.pack('!H', len(query)) + query)
                    resp = s.recv(struct.unpack('!H', s.recv(2))[0])
                ans, an_count, ns_recs, glue = parse_response(resp)
                if an_count > 0:
                    return ans, an_count
                next_s.extend(glue[n.lower()] for n in ns_recs if n.lower() in glue)
            except:
                continue
        if not next_s:
            break
        servers = next_s
    return None, 0


def process_query(data):
    tx_id = struct.unpack('!H', data[:2])[0]
    qname, offset = decode_domain(data, 12)
    ans, an_count = resolve(data)

    if an_count == 0:
        # Статус NXDOMAIN (ошибка: домен не найден)
        return struct.pack('!HHHHHH', tx_id, 0x8183, 1, 0, 0, 0) + data[12: offset + 4]

    return struct.pack('!HHHHHH', tx_id, 0x8180, 1, an_count, 0, 0) + data[12: offset + 4] + ans


def handle_tcp(conn):
    try:
        if length := conn.recv(2):
            data = conn.recv(struct.unpack('!H', length)[0])
            resp = process_query(data)
            conn.sendall(struct.pack('!H', len(resp)) + resp)
    except:
        pass
    finally:
        conn.close()


def run_udp():
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(('127.0.0.1', 5353))
    while True:
        data, addr = udp.recvfrom(512)
        response = process_query(data)
        udp.sendto(response, addr)


def run_tcp():
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.bind(('127.0.0.1', 5353))
    tcp.listen(5)
    while True:
        conn, _ = tcp.accept()
        threading.Thread(target=handle_tcp, args=(conn,)).start()


if __name__ == '__main__':
    threading.Thread(target=run_udp, daemon=True).start()
    threading.Thread(target=run_tcp, daemon=True).start()

    print('DNS running on 127.0.0.1:5353')
    threading.Event().wait()