import socket
import subprocess
import time


flag=True
while flag:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('www.google.com', 80))

    # send an HTTP request
    s.send(b"GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n")

    # receive the response
    response = s.recv(1024)
    print(response)
    dateProc = subprocess.Popen([ 'date' ])
    print(dateProc.pid)

    # close the connection
    s.close()
    time.sleep(10)
