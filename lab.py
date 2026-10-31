

import argparse
import csv
import datetime
import os
import random
import re
import socket
import ssl
import struct
import sys
import threading
import time

HOST = "127.0.0.1"
DNS_PORT, HTTP_PORT, DOH_PORT = 5300, 8053, 8443
RESOLVER_NAME = "doh.resolver.test"   
MARKER = "anonimitate"             
SUFFIX = "example"
LABEL_LENGTHS = [11, 18, 25, 32, 39, 46, 53, 60]   
PAD_BLOCK = 128                 
USED_PORTS = set()



def encode_name(name):
    out = b""
    for label in name.split("."):
        raw = label.encode("ascii")
        assert 0 < len(raw) <= 63
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(name, pad=False):
    """DNS A query. Size without padding = len(name) + 18 bytes."""
    qname = encode_name(name)
    msg_id = random.getrandbits(16)
    arcount = 1 if pad else 0
    msg = struct.pack("!HHHHHH", msg_id, 0x0100, 1, 0, 0, arcount) + qname + struct.pack("!HH", 1, 1)
    if pad:
        
        fixed = len(msg) + 11 + 4               
        pad_len = (-fixed) % PAD_BLOCK
        option = struct.pack("!HH", 12, pad_len) + b"\x00" * pad_len   
        msg += b"\x00" + struct.pack("!HHIH", 41, 1232, 0, len(option)) + option
    return msg


def build_response(query):
    """Minimal server answer: A record 127.0.0.1 (the OPT record of the query is ignored)."""
    i = 12
    while query[i] != 0:
        i += query[i] + 1
    qend = i + 1 + 4
    header = query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([127, 0, 0, 1])
    return header + query[12:qend] + answer


def http_request(body):
    """The exact request bytes the client sends (one sendall -> one TLS record)."""
    head = (f"POST /dns-query HTTP/1.1\r\nHost: {RESOLVER_NAME}\r\n"
            f"Content-Type: application/dns-message\r\nAccept: application/dns-message\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n")
    return head.encode("ascii") + body


def make_cert(out_dir):
    cert_path, key_path = os.path.join(out_dir, "cert.pem"), os.path.join(out_dir, "key.pem")
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, RESOLVER_NAME)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(RESOLVER_NAME)]), False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, True, False, False, False), True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .sign(key, hashes.SHA256()))
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return cert_path, key_path



def serve_udp(stop):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((HOST, DNS_PORT))
    s.settimeout(0.2)
    while not stop.is_set():
        try:
            data, addr = s.recvfrom(4096)
        except socket.timeout:
            continue
        s.sendto(build_response(data), addr)
    s.close()


def handle_conn(conn, ctx):
    try:
        if ctx:
            conn = ctx.wrap_socket(conn, server_side=True)
        conn.settimeout(5)
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                return
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        clen = int(re.search(rb"Content-Length:\s*(\d+)", head, re.I).group(1))
        while len(rest) < clen:
            chunk = conn.recv(4096)
            if not chunk:
                return
            rest += chunk
        body = build_response(rest[:clen])
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
                     b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
    except (OSError, ssl.SSLError, AttributeError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def serve_tcp(port, ctx, stop):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, port))
    srv.listen(64)
    srv.settimeout(0.2)
    while not stop.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        threading.Thread(target=handle_conn, args=(conn, ctx), daemon=True).start()
    srv.close()



def fresh_socket(kind):
    """Socket bound to a source port that has not been used in this run."""
    while True:
        s = socket.socket(socket.AF_INET, kind)
        s.bind((HOST, 0))
        port = s.getsockname()[1]
        if port not in USED_PORTS:
            USED_PORTS.add(port)
            return s, port
        s.close()


def read_all(s):
    data = b""
    while True:
        try:
            chunk = s.recv(4096)
        except (ssl.SSLError, OSError):
            break
        if not chunk:
            break
        data += chunk
    return data


def query_udp(name):
    s, port = fresh_socket(socket.SOCK_DGRAM)
    msg = build_query(name)
    s.settimeout(3)
    s.sendto(msg, (HOST, DNS_PORT))
    s.recvfrom(4096)
    s.close()
    return port, len(msg), 0


def query_tcp(name, tls_ctx, port_no, pad):
    s, port = fresh_socket(socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((HOST, port_no))
    if tls_ctx:
        s = tls_ctx.wrap_socket(s, server_hostname=RESOLVER_NAME)
    msg = build_query(name, pad)
    req = http_request(msg)
    s.sendall(req)                      # a single send -> a single TLS record
    reply = read_all(s)
    assert reply.startswith(b"HTTP/1.1 200"), "bad reply"
    s.close()
    return port, len(msg), len(req)



def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["run"])
    ap.add_argument("--reps", type=int, default=10, help="repetitions per (variant, length)")
    ap.add_argument("--out", default="lab_out", help="output directory (queries.csv, cert)")
    ap.add_argument("--keylog", default=None, help="write TLS secrets here (lets Wireshark decrypt DoH)")
    ap.add_argument("--no-wait", action="store_true", help="do not wait for Enter before sending")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    cert, key = make_cert(args.out)

    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    server_ctx.load_cert_chain(cert, key)
    client_ctx = ssl.create_default_context(cafile=cert)  
    client_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    if args.keylog:
        client_ctx.keylog_filename = args.keylog

    stop = threading.Event()
    for target in (lambda: serve_udp(stop),
                   lambda: serve_tcp(HTTP_PORT, None, stop),
                   lambda: serve_tcp(DOH_PORT, server_ctx, stop)):
        threading.Thread(target=target, daemon=True).start()
    time.sleep(0.5)

    print(f"Python {sys.version.split()[0]}, {ssl.OPENSSL_VERSION}")
    print("Servers: UDP %d, HTTP %d, DoH(TLS 1.3) %d on %s" % (DNS_PORT, HTTP_PORT, DOH_PORT, HOST))
    if not args.no_wait:
        input("START THE CAPTURE now (see the guide), then press Enter... ")

    variants = {
        "dns_udp": lambda n: query_udp(n),
        "http_plain": lambda n: query_tcp(n, None, HTTP_PORT, False),
        "doh": lambda n: query_tcp(n, client_ctx, DOH_PORT, False),
        "doh_pad": lambda n: query_tcp(n, client_ctx, DOH_PORT, True),
    }
    rows = []
    for rep in range(1, args.reps + 1):
        for variant, fn in variants.items():
            for k in LABEL_LENGTHS:
                name = MARKER + "x" * (k - len(MARKER)) + "." + SUFFIX
                port, dns_len, http_len = fn(name)
                rows.append([variant, rep, name, len(name), port, dns_len, http_len, f"{time.time():.6f}"])
                time.sleep(0.01)
    time.sleep(1.0)                    
    stop.set()

    path = os.path.join(args.out, "queries.csv")
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["variant", "rep", "name", "name_len", "client_port", "dns_len", "http_len", "t_unix"])
        w.writerows(rows)
    print(f"Done: {len(rows)} queries -> {path}. Now stop the capture (Ctrl+C in tshark).")


if __name__ == "__main__":
    main()