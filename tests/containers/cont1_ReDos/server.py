import socket
import random
import re
import time
test_list = [
    "aaaa",
    "aaaaaaaa",
    "aaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
evil_rex = r"^(a|a?)+b$"


def create_response():
    html_content = "<html><body><h1>Hello World!</h1></body></html>"
    for s in test_list:
        start_ts = time. perf_counter()
        re.search(evil_rex, s)
        stop_ts = time.perf_counter()
        print(f"Testing of {s} took {stop_ts - start_ts :0.4f} seconds ")
    response_headers = "HTTP/1.1 200 OK\nContent-Type: text/html\nContent-Length: {}\n\n".format(len(html_content))
    response_body = html_content.encode('utf-8')
    
    response = response_headers.encode('utf-8') + response_body
    
    return response

HOST = 'localhost'
PORT = 4200

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_socket.bind((HOST, PORT))

server_socket.listen()

print('Server listening on {}:{}'.format(HOST, PORT))

while True:
    client_socket, client_address = server_socket.accept()
    print('Received connection from {}:{}'.format(client_address[0], client_address[1]))
    
    request = client_socket.recv(1024)
    
    if request.startswith(b'GET'):
        response = create_response()
        time.sleep(15000)
        client_socket.sendall(response)
    
    client_socket.close()
