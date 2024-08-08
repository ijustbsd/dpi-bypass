import logging
import platform
import select
import socket
import struct
import time
from socketserver import StreamRequestHandler, TCPServer, ThreadingMixIn

SOCKS_VERSION = 5
HOST = "127.0.0.1"
PORT = 1080

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class SOCKS5RequestHandler(StreamRequestHandler):
    def greeting_handler(self):
        """
        https://datatracker.ietf.org/doc/html/rfc1928#section-3
        """
        version, nmethods = struct.unpack(">BB", self.connection.recv(2))
        assert version == SOCKS_VERSION
        _ = self.connection.recv(nmethods)
        self.connection.sendall(b"\x05\x00")

    def connection_handler(self):
        """
        https://datatracker.ietf.org/doc/html/rfc1928#section-4
        """
        version, cmd, _, address_type = struct.unpack(">BBBB", self.connection.recv(4))
        assert version == SOCKS_VERSION
        if cmd != 1:
            self.server.close_request(self.request)
            return
        match address_type:
            case 1:  # IPv4
                inet_type = socket.AF_INET
                address = socket.inet_ntop(inet_type, self.connection.recv(4))
            case 3:  # domain name
                inet_type = socket.AF_INET
                (domain_len,) = struct.unpack(">B", self.connection.recv(1))
                address = socket.gethostbyname(self.connection.recv(domain_len))
            case 4:  # IPv6
                inet_type = socket.AF_INET6
                address = socket.inet_ntop(inet_type, self.connection.recv(16))
            case _:
                raise RuntimeError
        (port,) = struct.unpack(">H", self.connection.recv(2))

        try:
            remote = socket.socket(inet_type, socket.SOCK_STREAM)
            remote.connect((address, port))
            logger.debug("Connected to remote %s:%s" % (address, port))
        except Exception as e:
            logger.error(e)
            self.connection.sendall(b"\x05\x05\x00\x01" + socket.inet_aton(HOST) + struct.pack(">H", PORT))
            return

        bnd_addr, bnd_port = remote.getsockname()
        self.connection.sendall(b"\x05\x00\x00\x01" + socket.inet_aton(bnd_addr) + struct.pack(">H", bnd_port))

        self.socks5_loop(self.connection, remote)

    def socks5_loop(self, client, remote):
        def_ttl = remote.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)

        while True:
            r, _, _ = select.select([client, remote], [], [])

            if client in r:
                data = client.recv(4096)
                if not data:
                    break

                if data[:2] != b"\x16\x03":  # https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
                    remote.sendall(data)
                    continue

                if platform.system() == "Linux":
                    remote.setsockopt(socket.SOL_IP, socket.IP_TTL, 1)
                    remote.sendall(data[:2])
                    remote.setsockopt(socket.SOL_IP, socket.IP_TTL, def_ttl)
                    remote.sendall(data[2:])
                else:
                    remote.setsockopt(socket.SOL_IP, socket.IP_TTL, def_ttl)
                    remote.sendall(data[:2])
                    remote.setsockopt(socket.SOL_IP, socket.IP_TTL, 1)
                    remote.sendall(data[2:8])
                    time.sleep(0.1)  # ensure that [2:8] and [8:] are sent in different TCP segments
                    remote.setsockopt(socket.SOL_IP, socket.IP_TTL, def_ttl)
                    remote.sendall(data[8:])

            if remote in r:
                data = remote.recv(4096)
                if not data:
                    break
                client.sendall(data)

    def handle(self):
        logger.debug("Connection from: %s:%s" % self.client_address)
        try:
            self.greeting_handler()
            self.connection_handler()
        except Exception:
            pass
        self.server.close_request(self.request)


if __name__ == "__main__":
    with ThreadingTCPServer((HOST, PORT), SOCKS5RequestHandler) as server:
        print(f"Listening SOCKS{SOCKS_VERSION} on {HOST} port {PORT} ...")
        server.serve_forever()
