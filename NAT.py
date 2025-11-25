#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional, Tuple, List
import argparse
import logging
import struct
import socket
import select
import time
import sys
import contextlib

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s [%(filename)s:%(lineno)d] %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger(__name__)

class N4Error(Exception):
    pass

class InvalidPacket(N4Error):
    pass

class PunchFailure(N4Error):
    pass

class N4Packet:
    SIZE = 8
    CMD_HELLO = 0x01
    CMD_READY = 0x02
    CMD_EXCHG = 0x03
    CMD_PINFO = 0x04
    CMD_PUNCH = 0x05
    RESERVED = 0x00
    _FMT_BB6 = "!BB6s"
    _FMT_BB4H = "!BB4sH"

    @classmethod
    def hello(cls, ident: bytes) -> bytes:
        return struct.pack(cls._FMT_BB6, cls.CMD_HELLO, cls.RESERVED, ident)

    @classmethod
    def dec_hello(cls, pkt: bytes) -> Optional[bytes]:
        if len(pkt) != cls.SIZE:
            return None
        cmd, _, ident = struct.unpack(cls._FMT_BB6, pkt)
        return ident if cmd == cls.CMD_HELLO else None

    @classmethod
    def ready(cls) -> bytes:
        return struct.pack(cls._FMT_BB6, cls.CMD_READY, cls.RESERVED, b"\x00" * 6)

    @classmethod
    def dec_ready(cls, pkt: bytes) -> bool:
        if len(pkt) != cls.SIZE:
            return False
        cmd, _, _ = struct.unpack(cls._FMT_BB6, pkt)
        return cmd == cls.CMD_READY

    @classmethod
    def exchange(cls, ident: bytes) -> bytes:
        return struct.pack(cls._FMT_BB6, cls.CMD_EXCHG, cls.RESERVED, ident)

    @classmethod
    def dec_exchange(cls, pkt: bytes) -> Optional[bytes]:
        if len(pkt) != cls.SIZE:
            return None
        cmd, _, ident = struct.unpack(cls._FMT_BB6, pkt)
        return ident if cmd == cls.CMD_EXCHG else None

    @classmethod
    def peerinfo(cls, peeraddr: Tuple[str, int]) -> bytes:
        ip, port = peeraddr
        ipb = socket.inet_aton(ip)
        return struct.pack(cls._FMT_BB4H, cls.CMD_PINFO, cls.RESERVED, ipb, port)

    @classmethod
    def dec_peerinfo(cls, pkt: bytes) -> Optional[Tuple[str, int]]:
        if len(pkt) != cls.SIZE:
            return None
        cmd, _, ipb, port = struct.unpack(cls._FMT_BB4H, pkt)
        if cmd != cls.CMD_PINFO:
            return None
        return (socket.inet_ntoa(ipb), port)

    @classmethod
    def punch(cls, ident: bytes) -> bytes:
        return struct.pack(cls._FMT_BB6, cls.CMD_PUNCH, cls.RESERVED, ident)

    @classmethod
    def dec_punch(cls, pkt: bytes) -> Optional[bytes]:
        if len(pkt) != cls.SIZE:
            return None
        cmd, _, ident = struct.unpack(cls._FMT_BB6, pkt)
        return ident if cmd == cls.CMD_PUNCH else None

class SocketPair:
    def __init__(self):
        self.tcp: Optional[socket.socket] = None
        self.udp: Optional[socket.socket] = None
        self._conns: List[socket.socket] = []

    def close_all(self):
        if self.tcp:
            with contextlib.suppress(Exception):
                self.tcp.close()
            self.tcp = None
        if self.udp:
            with contextlib.suppress(Exception):
                self.udp.close()
            self.udp = None
        while self._conns:
            s = self._conns.pop()
            with contextlib.suppress(Exception):
                s.close()

    def add_conn(self, s: socket.socket):
        self._conns.append(s)

    def clear_udp_buffer_nonblocking(self, udp_sock: socket.socket):
        try:
            udp_sock.setblocking(False)
            while True:
                try:
                    udp_sock.recvfrom(65535)
                except BlockingIOError:
                    break
                except Exception:
                    break
        finally:
            with contextlib.suppress(Exception):
                udp_sock.setblocking(True)

class N4Server:
    def __init__(self, ident: bytes, bind_port: int, accept_timeout: int = 60):
        self.ident = ident
        self.bind_port = bind_port
        self.accept_timeout = accept_timeout
        self.sockets = SocketPair()

    def _create_listeners(self):
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass
        tcp.bind(("0.0.0.0", self.bind_port))
        tcp.listen(5)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass
        udp.bind(("0.0.0.0", self.bind_port))
        self.sockets.tcp = tcp
        self.sockets.udp = udp
        logger.info("Listening on TCP/%d and UDP/%d", self.bind_port, self.bind_port)

    def _sock_same_peer_ip(self, sock: socket.socket, addr: Tuple[str, int], allow_cross_ip: bool) -> bool:
        try:
            peer_ip = sock.getpeername()[0]
            if peer_ip == addr[0]:
                return True
            return allow_cross_ip
        except Exception:
            return False

    def _accept_clients(self, max_clients: int = 2):
        tcp = self.sockets.tcp
        if not tcp:
            raise RuntimeError("tcp not initialized")
        tcp.setblocking(False)
        start = time.time()
        while len(self.sockets._conns) < max_clients:
            remaining = self.accept_timeout - (time.time() - start)
            if remaining <= 0:
                raise TimeoutError("timeout waiting for clients")
            r, _, _ = select.select([tcp], [], [], remaining)
            if not r:
                continue
            try:
                c, addr = tcp.accept()
                c.settimeout(10)
                try:
                    pkt = c.recv(N4Packet.SIZE)
                except socket.timeout:
                    with contextlib.suppress(Exception):
                        c.close()
                    continue
                ident = N4Packet.dec_hello(pkt)
                if ident == self.ident:
                    c.setblocking(True)
                    self.sockets.add_conn(c)
                    logger.info("Client accepted (%d/%d) from %s:%d", len(self.sockets._conns), max_clients, addr[0], addr[1])
                else:
                    with contextlib.suppress(Exception):
                        c.close()
            except Exception as e:
                logger.exception("accept error: %s", e)

    def serve(self, allow_cross_ip: bool = False):
        try:
            self._create_listeners()
            self._accept_clients()
            if self.sockets.udp:
                self.sockets.clear_udp_buffer_nonblocking(self.sockets.udp)
            ready_pkt = N4Packet.ready()
            for s in list(self.sockets._conns):
                with contextlib.suppress(Exception):
                    s.sendall(ready_pkt)
            ok = [False] * len(self.sockets._conns)
            try:
                udp = self.sockets.udp
                if not udp:
                    return
                while True:
                    try:
                        data, addr = udp.recvfrom(65535)
                    except Exception:
                        continue
                    if len(data) != N4Packet.SIZE:
                        logger.debug("ignore udp len=%d from %s:%d", len(data), addr[0], addr[1])
                        continue
                    ident = N4Packet.dec_exchange(data)
                    if ident is None:
                        logger.debug("ignore non-exchange from %s:%d", addr[0], addr[1])
                        continue
                    for idx, s in enumerate(self.sockets._conns):
                        if not ok[idx] and self._sock_same_peer_ip(s, addr, allow_cross_ip):
                            other_idx = 1 - idx if len(self.sockets._conns) >= 2 else None
                            if other_idx is None or other_idx >= len(self.sockets._conns):
                                continue
                            pkt = N4Packet.peerinfo(addr)
                            try:
                                self.sockets._conns[other_idx].sendall(pkt)
                                ok[idx] = True
                                logger.info("Notified %s:%d to conn[%d]", addr[0], addr[1], other_idx)
                            except Exception:
                                logger.exception("failed to send peerinfo")
                    if all(ok):
                        logger.info("exchange complete")
                        break
            except Exception as e:
                logger.exception("serve loop error: %s", e)
            finally:
                if self.sockets.udp:
                    self.sockets.clear_udp_buffer_nonblocking(self.sockets.udp)
        finally:
            self.sockets.close_all()

class N4Client:
    def __init__(self, ident: bytes, server_host: str, server_port: int, src_port_start: int, src_port_count: int, peer_port_offset: int, allow_cross_ip: bool, tcp_timeout: int = 10):
        self.ident = ident
        self.server_host = server_host
        self.server_port = server_port
        self.src_port_start = src_port_start
        self.src_port_count = max(1, src_port_count)
        self.peer_port_offset = peer_port_offset
        self.allow_cross_ip = allow_cross_ip
        self.tcp_timeout = tcp_timeout
        self.tcp_sock: Optional[socket.socket] = None
        self.pool: List[socket.socket] = []

    def _open_control(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.tcp_timeout)
        s.connect((self.server_host, self.server_port))
        self.tcp_sock = s

    def _open_pool(self):
        for i in range(self.src_port_count):
            port = 0
            if self.src_port_start:
                port = self.src_port_start + i
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except Exception:
                pass
            s.bind(("0.0.0.0", port))
            s.settimeout(0.5)
            self.pool.append(s)

    def _close_all(self):
        if self.tcp_sock:
            with contextlib.suppress(Exception):
                self.tcp_sock.close()
            self.tcp_sock = None
        while self.pool:
            s = self.pool.pop()
            with contextlib.suppress(Exception):
                s.close()

    def punch(self, wait: int = 10) -> Tuple[Tuple[str, int], int]:
        try:
            self._open_control()
            self._open_pool()
            hello = N4Packet.hello(self.ident)
            assert self.tcp_sock is not None
            self.tcp_sock.sendall(hello)
            logger.info("<= Hello (sent)")
            try:
                ready_pkt = self.tcp_sock.recv(N4Packet.SIZE)
            except socket.timeout:
                raise InvalidPacket("timeout waiting for ready")
            if not N4Packet.dec_ready(ready_pkt):
                raise InvalidPacket("invalid ready")
            logger.info("=> Ready (received)")
            exchg = N4Packet.exchange(self.ident)
            for _ in range(3):
                with contextlib.suppress(Exception):
                    self.pool[0].sendto(exchg, (self.server_host, self.server_port))
                time.sleep(0.05)
            logger.info("<= Exchange (sent)")
            try:
                pinfo_pkt = self.tcp_sock.recv(N4Packet.SIZE)
            except socket.timeout:
                raise InvalidPacket("timeout waiting for peerinfo")
            peer = N4Packet.dec_peerinfo(pinfo_pkt)
            if not peer:
                raise InvalidPacket("invalid peerinfo")
            peer_ip, peer_port = peer
            target = (peer_ip, peer_port + self.peer_port_offset)
            logger.info("=> Peer from server: %s:%d", peer_ip, peer_port)
            logger.info("   [ target -> %s:%d ]", target[0], target[1])
            punch_pkt = N4Packet.punch(self.ident)
            for _ in range(5):
                for s in self.pool:
                    with contextlib.suppress(Exception):
                        s.sendto(punch_pkt, target)
                time.sleep(0.05)
            logger.info("<= Punch (to target) sent")
            deadline = time.time() + wait
            recv_peer: Optional[Tuple[str, int]] = None
            recv_sock: Optional[socket.socket] = None
            while time.time() < deadline:
                timeout = max(0.0, deadline - time.time())
                rlist, _, _ = select.select(self.pool, [], [], timeout)
                if not rlist:
                    continue
                for s in rlist:
                    try:
                        data, addr = s.recvfrom(65535)
                    except socket.timeout:
                        continue
                    except Exception:
                        continue
                    if len(data) != N4Packet.SIZE:
                        logger.debug("ignore non-n4 len=%d from %s:%d", len(data), addr[0], addr[1])
                        continue
                    if N4Packet.dec_punch(data) is None:
                        logger.debug("ignore non-punch from %s:%d", addr[0], addr[1])
                        continue
                    if addr[0] == peer_ip or self.allow_cross_ip:
                        recv_peer = addr
                        recv_sock = s
                        break
                if recv_peer:
                    break
            if not recv_peer or not recv_sock:
                raise PunchFailure("timeout waiting for peer punch")
            logger.info("=> Received punch from peer %s:%d", recv_peer[0], recv_peer[1])
            for _ in range(6):
                with contextlib.suppress(Exception):
                    recv_sock.sendto(punch_pkt, recv_peer)
                time.sleep(0.05)
            local_port = recv_sock.getsockname()[1]
            logger.info("Local UDP port used: %d", local_port)
            return recv_peer, local_port
        finally:
            self._close_all()

def ident_t(a: str) -> bytes:
    b = str(a).encode("ascii", "ignore")[:6]
    if len(b) < 6:
        b = b.ljust(6, b' ')
    if len(b) != 6:
        raise argparse.ArgumentTypeError("identifier must be up to 6 ascii chars")
    return b

def srv_main(args: argparse.Namespace):
    ident = args.a
    port = args.l
    allow_cross_ip = args.x
    while True:
        try:
            srv = N4Server(ident, port, accept_timeout=60)
            srv.serve(allow_cross_ip=allow_cross_ip)
        except TimeoutError:
            logger.warning("accept timeout, restarting")
            time.sleep(1)
            continue
        except KeyboardInterrupt:
            logger.info("server stopped")
            break
        except Exception:
            logger.exception("server error, restarting")
            time.sleep(1)
            continue

def cli_main(args: argparse.Namespace):
    ident = args.a
    server_host = args.h
    server_port = args.p
    port = args.b
    count = args.n
    offset = args.o
    allow_cross_ip = args.x
    while True:
        try:
            client = N4Client(
                ident=ident,
                server_host=server_host,
                server_port=server_port,
                src_port_start=port,
                src_port_count=count,
                peer_port_offset=offset,
                allow_cross_ip=allow_cross_ip
            )
            logger.info("==================")
            logger.info("Source port range hint: %d - %d", port, (port + max(0, count - 1)))
            peer, src_port = client.punch(wait=10)
            peer_ip, peer_port = peer
            logger.info("------")
            logger.info("Local port:    %d", src_port)
            logger.info("Peer address:  %s:%d", peer_ip, peer_port)
            logger.info("------")
            logger.info("[ WIN ]")
            logger.info("nc -u -p %d %s %d", src_port, peer_ip, peer_port)
            break
        except PunchFailure:
            logger.info("[ LOSE ] 穿透失败，尝试下一个端口块")
            port += count
            time.sleep(0.3)
            continue
        except InvalidPacket as e:
            logger.error("protocol error: %s", e)
            break
        except KeyboardInterrupt:
            logger.info("client stopped")
            break
        except Exception:
            logger.exception("unknown error")
            break

def main():
    parser = argparse.ArgumentParser(prog="n4", description="N4 UDP hole punching tool", add_help=False)
    group = parser.add_argument_group("options")
    group.add_argument("-a", type=ident_t, metavar="<ident>", default=b"n4n4n4", help="identifier (up to 6 ASCII chars)")
    group.add_argument("--debug", action="store_true", help="enable debug logging")
    server_group = parser.add_argument_group("server options")
    server_group.add_argument("-s", action="store_true", help="run in server mode")
    server_group.add_argument("-l", type=int, metavar="<port>", default=1721, help="server listen port")
    client_group = parser.add_argument_group("client options")
    client_group.add_argument("-c", action="store_true", help="run in client mode")
    client_group.add_argument("-b", type=int, metavar="<port>", default=30000, help="source port start (0 means any)")
    client_group.add_argument("-n", type=int, metavar="<count>", default=25, help="source port count")
    client_group.add_argument("-o", type=int, metavar="<offset>", default=20, help="peer port offset")
    client_group.add_argument("-h", type=str, help="hostname of N4 server (required for client)", default=None)
    client_group.add_argument("-p", type=int, help="port of N4 server", default=1721)
    client_group.add_argument("-x", action="store_true", help="allow peer ip NOT get from server (allow cross ip)")
    parser.add_argument("-?", "--help", action="help", help="show this help message and exit")
    args = parser.parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)
    if args.s:
        srv_main(args)
    elif args.c:
        if not args.h:
            logger.error("client 模式需要指定 -h <server_host>")
            parser.print_help()
            sys.exit(2)
        cli_main(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
