import socket
import threading
import os
import signal
import sys

class Server:
    def __init__(self, hosts_file='hosts.txt', port=5454, max_levels=127):
        self.port = port
        self.max_levels = max_levels
        self.running = False
        self.server_socket = None
        self.domain_ip = {}
        
        
        self.load_hosts_file(hosts_file)

    def load_hosts_file(self, hosts_file):
        try:
            if os.path.exists(hosts_file):
                with open(hosts_file, 'r') as file:
                     for line in file:
                        parts = line.split()
                        if len(parts) == 2:
                            domain, ip = parts
                            self.domain_ip[domain] = ip
            else:
                #print("not found host file")
                print(f"{hosts_file} not found")
                
        except Exception as e:
            print(f"Error {hosts_file}: {e}")
            

    def is_valid_ip(self, ip):
        
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            return all(0 <= int(part) <= 255 for part in parts)
        except (AttributeError, TypeError, ValueError):
            return False

    def parse_dns_domain(self, data, offset):
        
        domain_parts = []
        current_offset = offset
        bytes_read = 0
        level_count = 0
        visited_pointers = set()

        while current_offset < len(data):
            if level_count >= self.max_levels:
                raise ValueError(f"Exceeded maximum levels: {self.max_levels}")
            
            length = data[current_offset]
            if length == 0:
                if bytes_read == 0:
                    bytes_read = current_offset - offset + 1
                break

                
            
            current_offset += 1
            if current_offset + length > len(data):
                raise ValueError(" packet boundary error")
                
            label = data[current_offset:current_offset + length]
            try:
                domain_parts.append(label.decode('utf-8'))
            except UnicodeDecodeError:
                raise ValueError(" label invalid")
                
            current_offset += length
            bytes_read = current_offset - offset + 1
            level_count += 1
        
        if not domain_parts:
            raise ValueError("Name Empty")
            
        return '.'.join(filter(None, domain_parts)), bytes_read

    def parse_dns_query(self, data):
        
        if len(data) < 12:
            raise ValueError("packet is too short")
            
        #transaction_id = (data[0] << 8) | data[1]
        transaction_id = data[0] * 256 + data[1]

        #flags = data[2] * 256 + data[3]
        flags = (data[2] << 8) | data[3]
        if (flags & 0x8000) != 0:
            raise ValueError("Not packet")
        
        try:
            domain_name, bytes_read = self.parse_dns_domain(data, 12)
            
            offset = 12 + bytes_read
            if offset + 4 > len(data):
                raise ValueError("packet truncated")
                
            query_type = (data[offset] << 8) | data[offset + 1]
            query_class = (data[offset + 2] << 8) | data[offset + 3]
            
            return transaction_id, domain_name, query_type, query_class
            
        except Exception as e:
            print(f"Error parsing: {e}")
            raise

def create_dns_response(self, query_data):
    
    try:
        transaction_id, domain_name, query_type, query_class = self.parse_dns_query(query_data)
        print(f"Looking for: {domain_name}")
        
        response = bytearray()
        
        #response.extend(divmod(transaction_id, 256))
        response.extend([transaction_id >> 8, transaction_id & 0xFF])
        
        
        if domain_name.lower() not in {k.lower() for k in self.domain_ip.keys()}:
            
            response.extend([0x81, 0x83])  
            print(f"Domain not found: {domain_name}")
        else:
            response.extend([0x81, 0x80])  
        
        
        response.extend([0x00, 0x01,   
                       0x00, 0x00,     
                       0x00, 0x00,     
                       0x00, 0x00])    
        
        
        question_end = 12 + self.parse_dns_domain(query_data, 12)[1] + 4
        response.extend(query_data[12:question_end])
        
        domain_exists = False
        for k in self.domain_ip.keys():
            if domain_name.lower() == k.lower():
                domain_exists = True
                break

        if not domain_exists:
            return bytes(response)

        response.extend([0xC0, 0x0C])  
        response.extend([0x00, 0x01,   
                       0x00, 0x01])    
        response.extend([0x00, 0x00,   
                       0x01, 0x2C])
        response.extend([0x00, 0x04])  
        
        
        for k in self.domain_ip.keys():
            if k.lower() == domain_name.lower():
                domain_key = k
                break

        ip = self.domain_ip[domain_key]
        ip_parts = [int(x) for x in ip.split('.')]
        response.extend(ip_parts)
        
        print(f"found: {ip} for {domain_name}")
        return bytes(response)
        
    except Exception as e:
        print(f"Error crafting: {e}")
        return None

    def handle_query(self, client_socket, client_addr, data):
        """Handle individual DNS queries"""
        try:
            response = self.create_dns_response(data)
            if response and self.running:
                client_socket.sendto(response, client_addr)
        except Exception as e:
            print(f"Error query")

    def stop_server(self, signum=None, frame=None):

        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception as e:
                print(f"socket error: {e}")

        sys.exit(0)

    def start_server(self):
        """Start the DNS server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.server_socket.bind(('', self.port))
            
        
            self.server_socket.settimeout(1.0)
            self.running = True
            print(f"\n Server started on port {self.port}\n")
                        
            while self.running:
                try:
                    data, client_addr = self.server_socket.recvfrom(512)
                   
                    
                    thread = threading.Thread(
                        target=self.handle_query,
                        args=(self.server_socket, client_addr, data)
                    )
                    thread.daemon = True
                    thread.start()
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"Error receiving data: {e}")
                    
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            self.stop_server()

def main():
    server = Server(hosts_file='hosts.txt', port=5454)
    server.start_server()

if __name__ == "__main__":
    main()
