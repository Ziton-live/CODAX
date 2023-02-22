import socket

# create a TCP socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# connect to google.com on port 80
s.connect(('www.google.com', 80))

# send an HTTP request
s.send(b"GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n")

# receive the response
response = s.recv(1024)
print(response)

# close the connection
s.close()
