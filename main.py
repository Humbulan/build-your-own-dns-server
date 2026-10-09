import socket
import struct
import sys
import argparse
import pymysql
import threading
import queue
import time
from prometheus_client import CollectorRegistry, Counter, Histogram, push_to_gateway

# ============================================================
# CONFIG
# ============================================================
DB_HOST = '127.0.0.1'
DB_USER = 'root'
DB_PASS = 'RootStrongPass123!'
DB_NAME = 'imperial_nexus'
DB_PORT = 3306
PUSHGATEWAY = 'localhost:9092'
JOB_NAME = 'dns_server'
INSTANCE = 'imperial-dns-01'

# ============================================================
# PROMETHEUS METRICS
# ============================================================
prom_registry = CollectorRegistry()
prom_queries   = Counter('dns_queries_total', 'Total DNS queries',
                         ['domain', 'qtype', 'status'], registry=prom_registry)
prom_blocked   = Counter('dns_blocked_total', 'Blocked DNS queries',
                         ['domain'], registry=prom_registry)
prom_forwarded = Counter('dns_forwarded_total', 'Forwarded DNS queries',
                         registry=prom_registry)
prom_latency   = Histogram('dns_latency_seconds', 'DNS forwarding latency',
                           buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0],
                           registry=prom_registry)

# ============================================================
# BLOCKLIST (in-memory cache, refreshed from DB)
# ============================================================
blocklist_cache = set()
blocklist_lock = threading.Lock()

def load_blocklist():
    global blocklist_cache
    try:
        conn = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASS,
                               database=DB_NAME, port=DB_PORT, connect_timeout=2)
        with conn.cursor() as cur:
            cur.execute("SELECT domain_pattern FROM dns_blocklist WHERE enabled = 1")
            rows = cur.fetchall()
        conn.close()
        with blocklist_lock:
            blocklist_cache = {r[0].lower() for r in rows}
        if len(blocklist_cache) != globals().get("_last_bl_count", -1):
            globals()["_last_bl_count"] = len(blocklist_cache)
            print(f"[Blocklist] Loaded {len(blocklist_cache)} rules")
    except Exception as e:
        print(f"[Blocklist] Load failed: {e}")

def is_blocked(domain):
    d = domain.lower()
    with blocklist_lock:
        rules = list(blocklist_cache)
    for rule in rules:
        if d == rule or d.endswith('.' + rule):
            return True
    return False

def blocklist_refresh_worker():
    load_blocklist()
    while True:
        time.sleep(60)
        load_blocklist()

# ============================================================
# PROMETHEUS PUSH WORKER
# ============================================================
def prometheus_push_worker():
    while True:
        time.sleep(15)
        try:
            push_to_gateway(PUSHGATEWAY, job=JOB_NAME, registry=prom_registry)
        except Exception as e:
            print(f"[Prom] Push failed: {e}")

# ============================================================
# DNS PARSING / BUILDING
# ============================================================
def parse_arguments():
    parser = argparse.ArgumentParser(description='DNS Forwarding Server')
    parser.add_argument('--resolver', required=True, help='Resolver address IP:PORT')
    return parser.parse_args()

def parse_dns_header(data):
    if len(data) < 12:
        return None
    id, flags, qdcount, ancount, nscount, arcount = struct.unpack('>HHHHHH', data[:12])
    return {
        'id': id, 'qr': (flags >> 15) & 0x1, 'opcode': (flags >> 11) & 0xF,
        'aa': (flags >> 10) & 0x1, 'tc': (flags >> 9) & 0x1,
        'rd': (flags >> 8) & 0x1, 'ra': (flags >> 7) & 0x1,
        'z': (flags >> 4) & 0x7, 'rcode': flags & 0xF,
        'qdcount': qdcount, 'ancount': ancount,
        'nscount': nscount, 'arcount': arcount
    }

def parse_domain_name(data, offset):
    labels = []
    while offset < len(data):
        length = data[offset]; offset += 1
        if length == 0: break
        elif length & 0xC0 == 0xC0:
            ptr = ((length & 0x3F) << 8) | data[offset]; offset += 1
            cl, _ = parse_domain_name(data, ptr); labels.extend(cl); break
        else:
            labels.append(data[offset:offset+length]); offset += length
    return labels, offset

def parse_dns_questions(data, qdcount, start_offset=12):
    questions = []
    offset = start_offset
    for _ in range(qdcount):
        labels, offset = parse_domain_name(data, offset)
        dnb = b''
        for label in labels:
            dnb += bytes([len(label)]) + label
        dnb += b'\x00'
        if offset + 4 > len(data): break
        qtype = struct.unpack('>H', data[offset:offset+2])[0]; offset += 2
        qclass = struct.unpack('>H', data[offset:offset+2])[0]; offset += 2
        questions.append({'domain_name': dnb, 'qtype': qtype, 'qclass': qclass, 'labels': labels})
    return questions, offset

def build_dns_header(id, qdcount=1, ancount=0, is_response=True, opcode=0, rd=0, rcode=0):
    flags = 0
    if is_response: flags |= (1 << 15)
    flags |= (opcode << 11); flags |= (rd << 8); flags |= rcode
    return struct.pack('>HHHHHH', id, flags, qdcount, ancount, 0, 0)

def build_dns_question(question):
    return question['domain_name'] + struct.pack('>HH', question['qtype'], question['qclass'])

def build_sinkhole_response(original_header, question):
    """Return 0.0.0.0 for the queried domain (blocked)."""
    header = build_dns_header(original_header['id'], qdcount=1, ancount=1,
                              is_response=True, opcode=original_header['opcode'],
                              rd=original_header['rd'], rcode=0)
    q_bytes = build_dns_question(question)
    answer = (question['domain_name'] +
              struct.pack('>H', 1) +                     # Type A
              struct.pack('>H', 1) +                     # Class IN
              struct.pack('>I', 60) +                    # TTL
              struct.pack('>H', 4) +                     # rdlength
              struct.pack('>BBBB', 0, 0, 0, 0))          # 0.0.0.0
    return header + q_bytes + answer

# ============================================================
# DB LOGGING
# ============================================================
QTYPE_MAP = {1:'A',2:'NS',5:'CNAME',6:'SOA',12:'PTR',15:'MX',16:'TXT',28:'AAAA',33:'SRV',255:'ANY'}
log_queue = queue.Queue(maxsize=2000)

def db_log_worker():
    conn = None
    while True:
        entry = log_queue.get()
        if entry is None: break
        if conn is None:
            try:
                conn = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASS,
                                       database=DB_NAME, port=DB_PORT,
                                       connect_timeout=2, autocommit=True)
            except Exception as e:
                print(f"[DB Log] Connect failed: {e}"); conn = None; continue
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO dns_query_logs "
                    "(client_ip, domain_name, query_type, response_status, latency_ms, blocked) "
                    "VALUES (%s, %s, %s, %s, %s, %s)",
                    entry
                )
        except Exception as e:
            print(f"[DB Log] Insert failed: {e}")
            try: conn.close()
            except: pass
            conn = None
    if conn:
        try: conn.close()
        except: pass

def log_dns_query(client_ip, domain, qtype, status="NOERROR", latency_ms=None, blocked=0):
    try:
        log_queue.put_nowait((client_ip, domain, qtype, status, latency_ms, blocked))
    except queue.Full:
        pass

def extract_domain_str(dnb):
    try:
        parts = []; i = 0
        while i < len(dnb):
            l = dnb[i]
            if l == 0: break
            i += 1
            parts.append(dnb[i:i+l].decode('ascii', errors='replace')); i += l
        return '.'.join(parts)
    except Exception:
        return '?'

# ============================================================
# FORWARDING
# ============================================================
def forward_single_query(question_data, resolver_addr, resolver_port, query_id):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2.0)
        s.sendto(question_data, (resolver_addr, resolver_port))
        data, _ = s.recvfrom(512)
        s.close()
        return data
    except socket.timeout:
        print(f"Timeout for query {query_id}"); return None
    except Exception as e:
        print(f"Error forwarding {query_id}: {e}"); return None

# ============================================================
# MAIN
# ============================================================
def main():
    args = parse_arguments()
    resolver_addr, resolver_port_str = args.resolver.split(':', 1)
    resolver_port = int(resolver_port_str)

    print(f"Starting DNS forwarding server on port 2053")
    print(f"Forwarding to resolver: {resolver_addr}:{resolver_port}")

    threading.Thread(target=db_log_worker, daemon=True).start()
    print("DB logging thread started")
    threading.Thread(target=blocklist_refresh_worker, daemon=True).start()
    print("Blocklist refresh thread started")
    threading.Thread(target=prometheus_push_worker, daemon=True).start()
    print(f"Prometheus push thread started (gateway={PUSHGATEWAY})")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(("127.0.0.1", 2053))

    query_counter = 1000

    while True:
        try:
            data, client_addr = server_socket.recvfrom(512)
            client_ip = client_addr[0]

            original_header = parse_dns_header(data)
            if not original_header: continue

            questions, _ = parse_dns_questions(data, original_header['qdcount'])
            if not questions: continue

            # Handle each question individually
            for question in questions:
                domain = extract_domain_str(question['domain_name'])
                qtype_str = QTYPE_MAP.get(question['qtype'], str(question['qtype']))

                # Blocklist check
                if is_blocked(domain):
                    print(f"[BLOCKED] {domain}")
                    sinkhole = build_sinkhole_response(original_header, question)
                    server_socket.sendto(sinkhole, client_addr)
                    log_dns_query(client_ip, domain, qtype_str, "BLOCKED", 0.0, 1)
                    prom_blocked.labels(domain=domain).inc()
                    prom_queries.labels(domain=domain, qtype=qtype_str, status="BLOCKED").inc()
                    continue

                # Forward and measure latency
                if len(questions) == 1:
                    start = time.time()
                    forward_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    forward_socket.settimeout(2.0)
                    try:
                        forward_socket.sendto(data, (resolver_addr, resolver_port))
                        resolver_data, _ = forward_socket.recvfrom(512)
                        latency = time.time() - start
                        server_socket.sendto(resolver_data, client_addr)
                        log_dns_query(client_ip, domain, qtype_str, "NOERROR", latency*1000, 0)
                        prom_latency.observe(latency)
                        prom_forwarded.inc()
                        prom_queries.labels(domain=domain, qtype=qtype_str, status="NOERROR").inc()
                        print(f"[FWD] {domain} -> {latency*1000:.1f}ms")
                    except socket.timeout:
                        err_flags = (1 << 15) | 2
                        err_hdr = struct.pack('>HHHHHH', original_header['id'], err_flags, 1, 0, 0, 0)
                        server_socket.sendto(err_hdr + data[12:], client_addr)
                        log_dns_query(client_ip, domain, qtype_str, "SERVFAIL", 2000.0, 0)
                        prom_queries.labels(domain=domain, qtype=qtype_str, status="SERVFAIL").inc()
                    finally:
                        forward_socket.close()
                else:
                    # Multi-question: forward individually
                    query_counter += 1
                    qh = build_dns_header(query_counter, qdcount=1, ancount=0,
                                          is_response=False,
                                          opcode=original_header['opcode'],
                                          rd=original_header['rd'])
                    qd = qh + build_dns_question(question)
                    start = time.time()
                    resp = forward_single_query(qd, resolver_addr, resolver_port, query_counter)
                    latency = time.time() - start
                    if resp:
                        # Rebuild header with original ID
                        fixed = struct.pack('>H', original_header['id']) + resp[2:]
                        server_socket.sendto(fixed, client_addr)
                        log_dns_query(client_ip, domain, qtype_str, "NOERROR", latency*1000, 0)
                        prom_latency.observe(latency)
                        prom_forwarded.inc()
                        prom_queries.labels(domain=domain, qtype=qtype_str, status="NOERROR").inc()
                    else:
                        log_dns_query(client_ip, domain, qtype_str, "SERVFAIL", None, 0)
                        prom_queries.labels(domain=domain, qtype=qtype_str, status="SERVFAIL").inc()

        except KeyboardInterrupt:
            print("\nShutting down...")
            log_queue.put(None)
            break
        except Exception as e:
            print(f"Error: {e}")
            continue

if __name__ == "__main__":
    main()
