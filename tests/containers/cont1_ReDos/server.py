# import socket
# import random
import re
# import time
import random

ATTACK_STRING_LENGTH = 50
# HOST = 'localhost'
# PORT = 8080



# def do_evil():
#     evil_rex = r"^(a|a?)+b$"
#     length = random.randint(25, ATTACK_STRING_LENGTH)
#     string = ''.join(random.choices(['a'], k=length))
#     print(string)
#     print(re.search(evil_rex, string))

# def create_response():
#     html_content = "<html><body>Done</body></html>"
#     response_headers = "HTTP/1.1 200 OK\nContent-Type: text/html\nContent-Length: {}\n\n".format(len(html_content))
#     response_body = html_content.encode('utf-8')
#     response = response_headers.encode('utf-8') + response_body
#     return response

# def config_server():
#     server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#     server_socket.bind((HOST, PORT))
#     server_socket.listen()
#     # server_socket.settimeout(30)
#     print('Server listening on {}:{}'.format(HOST, PORT))
#     return server_socket

# def main():
#     server_socket = config_server()
#     while True:
#         client_socket, client_address = server_socket.accept()
#         print('Received connection from {}:{}'.format(client_address[0], client_address[1]))
#         request = client_socket.recv(1024)
#         if request.startswith(b'GET'):
#             request = request.decode('utf-8')
#             if '/normal' in request:
#                 print("Normal request")
#             if '/attack' in request:
#                 do_evil();
#             response = create_response()
#             client_socket.sendall(response)
#         client_socket.close()



# if __name__ == '__main__':
#     main()
from flask import Flask

app = Flask(__name__)

@app.route("/")
def hello():
    return "Hello, World!"
@app.route("/attack")
def do_evil():
    evil_rex = r"^(a|a?)+b$"
    length = random.randint(35, ATTACK_STRING_LENGTH)
    string = ''.join(random.choices(['a'], k=length))
    print(string)
    print(re.search(evil_rex, string))
    return string

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8081)