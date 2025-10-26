import socket
import struct
import sys
import argparse

def parse_arguments():
    parser = argparse.ArgumentParser(description='DNS Forwarding Server')
    parser.add_argument('--resolver', required=True, help='Resolver address in format IP:PORT')
    return parser.parse_args()

def parse_dns_header(data):
    """Parse DNS header from received data"""
    if len(data) < 12:
        return None
    id, flags, qdcount, ancount, nscount, arcount = struct.unpack('>HHHHHH', data[:12])
    
    qr = (flags >> 15) & 0x1
    opcode = (flags >> 11) & 0xF
    aa = (flags >> 10) & 0x1
    tc = (flags >> 9) & 0x1
    rd = (flags >> 8) & 0x1
    ra = (flags >> 7) & 0x1
    z = (flags >> 4) & 0x7
    rcode = flags & 0xF
    
    return {
        'id': id,
        'qr': qr,
        'opcode': opcode,
        'aa': aa,
        'tc': tc,
        'rd': rd,
        'ra': ra,
        'z': z,
        'rcode': rcode,
        'qdcount': qdcount,
        'ancount': ancount,
        'nscount': nscount,
        'arcount': arcount
    }

def parse_domain_name(data, offset):
    """Parse domain name, handling compression pointers"""
    labels = []
    original_offset = offset
    
    while offset < len(data):
        length = data[offset]
        offset += 1
        
        if length == 0:
            break
        elif length & 0xC0 == 0xC0:
            pointer_offset = ((length & 0x3F) << 8) | data[offset]
            offset += 1
            compressed_labels, _ = parse_domain_name(data, pointer_offset)
            labels.extend(compressed_labels)
            break
        else:
            label = data[offset:offset+length]
            labels.append(label)
            offset += length
    
    return labels, offset

def parse_dns_questions(data, qdcount, start_offset=12):
    """Parse all DNS question sections from received data"""
    questions = []
    offset = start_offset
    
    for i in range(qdcount):
        labels, offset = parse_domain_name(data, offset)
        
        domain_name_bytes = b''
        for label in labels:
            domain_name_bytes += bytes([len(label)]) + label
        domain_name_bytes += b'\x00'
        
        if offset + 4 > len(data):
            break
            
        qtype = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        qclass = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        
        questions.append({
            'domain_name': domain_name_bytes,
            'qtype': qtype,
            'qclass': qclass,
            'offset': start_offset
        })
        start_offset = offset
    
    return questions, offset

def build_dns_header(id, qdcount=1, ancount=0, is_response=True, opcode=0, rd=0):
    """Build DNS header"""
    flags = 0
    if is_response:
        flags |= (1 << 15)
    flags |= (opcode << 11)
    flags |= (rd << 8)
    
    return struct.pack('>HHHHHH', id, flags, qdcount, ancount, 0, 0)

def build_dns_question(question):
    """Build a single question section"""
    return question['domain_name'] + struct.pack('>HH', question['qtype'], question['qclass'])

def forward_single_query(question_data, resolver_addr, resolver_port, query_id):
    """Forward a single question to resolver and return response"""
    try:
        forward_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        forward_socket.settimeout(2.0)
        
        forward_socket.sendto(question_data, (resolver_addr, resolver_port))
        resolver_data, _ = forward_socket.recvfrom(512)
        forward_socket.close()
        
        return resolver_data
    except socket.timeout:
        print(f"Timeout waiting for resolver for query {query_id}")
        return None
    except Exception as e:
        print(f"Error forwarding query {query_id}: {e}")
        return None

def main():
    args = parse_arguments()
    
    # Parse resolver address
    resolver_addr, resolver_port_str = args.resolver.split(':', 1)
    resolver_port = int(resolver_port_str)
    
    print(f"Starting DNS forwarding server on port 2053")
    print(f"Forwarding to resolver: {resolver_addr}:{resolver_port}")
    
    # Create server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(("127.0.0.1", 2053))
    
    query_counter = 1000
    
    while True:
        try:
            # Receive DNS query from client
            data, client_addr = server_socket.recvfrom(512)
            print(f"Received {len(data)} bytes from client {client_addr}")
            
            # Parse the original query header
            original_header = parse_dns_header(data)
            if not original_header:
                print("Invalid DNS header")
                continue
            
            # Parse all questions
            questions, _ = parse_dns_questions(data, original_header['qdcount'])
            print(f"Found {len(questions)} questions in query")
            
            if len(questions) == 1:
                # Single question - forward directly
                forward_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                forward_socket.settimeout(2.0)
                
                try:
                    forward_socket.sendto(data, (resolver_addr, resolver_port))
                    resolver_data, _ = forward_socket.recvfrom(512)
                    
                    # Send response back to client
                    server_socket.sendto(resolver_data, client_addr)
                    print("Sent single response back to client")
                    
                except socket.timeout:
                    print("Timeout waiting for resolver")
                    # Send error response
                    if len(data) >= 12:
                        query_id = struct.unpack('>H', data[0:2])[0]
                        error_flags = (1 << 15) | 2  # QR=1, RCODE=2
                        error_header = struct.pack('>HHHHHH', query_id, error_flags, 1, 0, 0, 0)
                        error_response = error_header + data[12:]
                        server_socket.sendto(error_response, client_addr)
                        print("Sent error response to client")
                finally:
                    forward_socket.close()
                    
            else:
                # Multiple questions - handle each separately
                print(f"Handling {len(questions)} questions separately")
                responses = []
                
                for i, question in enumerate(questions):
                    query_counter += 1
                    # Build individual query for this question
                    query_header = build_dns_header(
                        query_counter,
                        qdcount=1,
                        ancount=0,
                        is_response=False,
                        opcode=original_header['opcode'],
                        rd=original_header['rd']
                    )
                    query_data = query_header + build_dns_question(question)
                    
                    resolver_response = forward_single_query(
                        query_data, resolver_addr, resolver_port, query_counter
                    )
                    
                    if resolver_response:
                        responses.append((question, resolver_response))
                        print(f"Got response for question {i+1}")
                    else:
                        print(f"No response for question {i+1}")
                
                if responses:
                    # Build merged response
                    total_answers = 0
                    for _, resp_data in responses:
                        resp_header = parse_dns_header(resp_data)
                        if resp_header:
                            total_answers += resp_header['ancount']
                    
                    # Build response header
                    response_header = build_dns_header(
                        original_header['id'],
                        qdcount=len(questions),
                        ancount=total_answers,
                        is_response=True,
                        opcode=original_header['opcode'],
                        rd=original_header['rd']
                    )
                    
                    # Build question section (all questions)
                    question_section = b''.join(build_dns_question(q) for q in questions)
                    
                    # Build answer section (all answers)
                    answer_section = b''
                    for question, resp_data in responses:
                        resp_header = parse_dns_header(resp_data)
                        if resp_header and resp_header['ancount'] > 0:
                            # Extract answer section from response
                            # Find where answer section starts
                            q_start = 12
                            for j in range(resp_header['qdcount']):
                                _, q_end = parse_domain_name(resp_data, q_start)
                                q_start = q_end + 4
                            
                            answer_section += resp_data[q_start:]
                    
                    merged_response = response_header + question_section + answer_section
                    server_socket.sendto(merged_response, client_addr)
                    print(f"Sent merged response with {total_answers} answers")
                else:
                    # Send error response
                    error_header = build_dns_header(
                        original_header['id'],
                        qdcount=len(questions),
                        ancount=0,
                        is_response=True
                    )
                    error_questions = b''.join(build_dns_question(q) for q in questions)
                    server_socket.sendto(error_header + error_questions, client_addr)
                    print("Sent error response for multiple questions")
                
        except KeyboardInterrupt:
            print("\nShutting down server...")
            break
        except Exception as e:
            print(f"Error: {e}")
            continue

if __name__ == "__main__":
    main()
