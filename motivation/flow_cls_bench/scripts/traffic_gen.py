import socket

ifname = 'xdptut-7806'
msg = b"N\x10\x16gq#\xf2f\xf2j\x84S\x08\x00E\x00\x00'\x00\x01\x00\x00@\x11h\xa9\xc0\xa8\xc8e\xc0\xa8\xc8e\xc3\xcb\x1f\x90\x00\x13x\x81hello world"

sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode())
sock.send(msg)

