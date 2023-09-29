import random
import string
import socket

def generate_random_ip(subnet="192.168"):
    return f"{subnet}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

def generate_random_keyword(min_length=1, max_length=10):
    length = random.randint(min_length, max_length)
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))

def send_tcp_packets_socket(target_ip, target_port, num_packets_per_ip=10, num_ips=10):
    for _ in range(num_ips):
        src_ip = generate_random_ip()
        for _ in range(num_packets_per_ip):
            keyword_data = generate_random_keyword()
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((target_ip, target_port))

            # Güncellenmiş IP başlığı oluşturuluyor
            src_ip_bytes = [int(b) for b in src_ip.split(".")]
            ip_header = bytes([0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00] + src_ip_bytes + [0xAC, 0x11, 0x00, 0x02])

            client_socket.send(ip_header)
            client_socket.send(keyword_data.encode())
            client_socket.shutdown(socket.SHUT_RDWR) 
            client_socket.close()
            print(f"Sent packet from {src_ip} to {target_ip} with keyword: {keyword_data}")

if __name__ == "__main__":
    target_ip = "172.17.0.2"
    target_port = 80
    num_packets_per_ip = 1
    num_ips = 1000
    send_tcp_packets_socket(target_ip, target_port, num_packets_per_ip, num_ips)
