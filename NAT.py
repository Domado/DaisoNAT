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

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s [%(filename)s:%(lineno)d] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)

class N4Error(Exception):
    pass

class InvalidPacket(N4Error):
    pass

class PunchFailure(N4Error):
    pass

class N4Packet:
    """
    Packet format: total 8 bytes
      [ cmd (1) | reserved (1) | payload (6) ]
    For peerinfo we use: [ cmd (1) | reserved (1) | ipv4 (4) | port (2) ]
    """
    SIZE      = 8

    CMD_HELLO = 0x01    # client --TCP-> server (ident 6 bytes)
    CMD_READY = 0x02    # client <-TCP-- server (no payload)
    CMD_EXCHG = 0x03    # client --UDP-> server (ident 6 bytes)
    CMD_PINFO = 0x04    # client <-TCP-- server (ip4 + port)
    CMD_PUNCH = 0x05    # client <-UDP-> client (ident 6 bytes)

    RESERVED  = 0x00

    @staticmethod
    def hello(ident: bytes) -> bytes:
        assert len(ident) == 6
        return struct.pack("!BB6s", N4Packet.CMD_HELLO, N4Packet.RESERVED, ident)

    @staticmethod
    def dec_hello(pkt: bytes) -> Optional[bytes]:
        if len(pkt) != N4Packet.SIZE:
            return None
        cmd, _, ident = struct.unpack("!BB6s", pkt)
        if cmd != N4Packet.CMD_HELLO:
            return None
        return ident

    @staticmethod
    def ready() -> bytes:
        return struct.pack("!BB6s", N4Packet.CMD_READY, N4Packet.RESERVED, b"\x00"*6)

    @staticmethod
    def dec_ready(pkt: bytes) -> bool:
        if len(pkt) != N4Packet.SIZE:
            return False
        cmd, _, _ = struct.unpack("!BB6s", pkt)
        return cmd == N4Packet.CMD_READY

    @staticmethod
    def exchange(ident: bytes) -> bytes:
        assert len(ident) == 6
        return struct.pack("!BB6s", N4Packet.CMD_EXCHG, N4Packet.RESERVED, ident)

    @staticmethod
    def dec_exchange(pkt: bytes) -> Optional[bytes]:
        if len(pkt) != N4Packet.SIZE:
            return None
        cmd, _, ident = struct.unpack("!BB6s", pkt)
        if cmd != N4Packet.CMD_EXCHG:
            return None
        return ident

    @staticmethod
    def peerinfo(peeraddr: Tuple[str, int]) -> bytes:
        ip, port = peeraddr
        ipb = socket.inet_aton(ip)
        return struct.pack("!BB4sH", N4Packet.CMD_PINFO, N4Packet.RESERVED, ipb, port)

    @staticmethod
    def dec_peerinfo(pkt: bytes) -> Optional[Tuple[str, int]]:
        if len(pkt) != N4Packet.SIZE:
            return None
        cmd, _, ipb, port = struct.unpack("!BB4sH", pkt)
        if cmd != N4Packet.CMD_PINFO:
            return None
        ip = socket.inet_ntoa(ipb)
        return (ip, port)

    @staticmethod
    def punch(ident: bytes) -> bytes:
        assert len(ident) == 6
        return struct.pack("!BB6s", N4Packet.CMD_PUNCH, N4Packet.RESERVED, ident)

    @staticmethod
    def dec_punch(pkt: bytes) -> Optional[bytes]:
        if len(pkt) != N4Packet.SIZE:
            return None
        cmd, _, ident = struct.unpack("!BB6s", pkt)
        if cmd != N4Packet.CMD_PUNCH:
            return None
        return ident

# ---------- server ----------
class N4Server:
    def __init__(self, ident: bytes, bind_port: int, accept_timeout: int = 60) -> None:
        self.ident = ident
        self.bind_port = bind_port
        self.accept_timeout = accept_timeout
        self.tcp_sock: Optional[socket.socket] = None
        self.udp_sock: Optional[socket.socket] = None
        self.conn: List[socket.socket] = []

    def _init_sock(self) -> None:
        # TCP listening socket
        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass
        self.tcp_sock.bind(("0.0.0.0", self.bind_port))
        self.tcp_sock.listen(5)

        # UDP socket
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass
        self.udp_sock.bind(("0.0.0.0", self.bind_port))

        logger.info("Listening on TCP/%d and UDP/%d", self.bind_port, self.bind_port)

    def _close_all_sock(self) -> None:
        if self.tcp_sock:
            try:
                self.tcp_sock.close()
            except Exception:
                pass
            self.tcp_sock = None
        if self.udp_sock:
            try:
                self.udp_sock.close()
            except Exception:
                pass
            self.udp_sock = None
        while self.conn:
            s = self.conn.pop()
            try:
                s.close()
            except Exception:
                pass

    def _clear_udp_buff(self) -> None:
        # 非阻塞方式清空 UDP 接收缓冲区
        if not self.udp_sock:
            return
        try:
            self.udp_sock.setblocking(False)
            while True:
                try:
                    self.udp_sock.recvfrom(65535)
                except BlockingIOError:
                    break
                except Exception:
                    break
        finally:
            try:
                self.udp_sock.setblocking(True)
            except Exception:
                pass

    @staticmethod
    def _sock_same_peer_ip(sock: socket.socket, addr: Tuple[str, int], allow_cross_ip: bool = False) -> bool:
        # 如果 sock 没有 peername（可能未连接）则返回 False
        try:
            peer = sock.getpeername()
            peer_ip = peer[0]
            if peer_ip == addr[0]:
                return True
            if allow_cross_ip:
                # 若允许交叉IP，则仍视为同一对端（更宽松）
                return True
            return False
        except Exception:
            return False

    def _wait_clients(self, max_clients: int = 2) -> None:
        """
        等待 max_clients 个符合 ident 的 TCP 客户端连入。
        使用 select 以避免永久阻塞。
        """
        if not self.tcp_sock:
            raise RuntimeError("TCP socket not initialized")
        self.tcp_sock.setblocking(False)
        start = time.time()
        while len(self.conn) < max_clients:
            remaining = self.accept_timeout - (time.time() - start)
            if remaining <= 0:
                raise TimeoutError("Timeout waiting for clients")
            r, _, _ = select.select([self.tcp_sock], [], [], remaining)
            if not r:
                continue
            try:
                c, addr = self.tcp_sock.accept()
                logger.info("New TCP connection from %s:%d", addr[0], addr[1])
                c.settimeout(10)
                try:
                    hello = c.recv(N4Packet.SIZE)
                except socket.timeout:
                    logger.warning("Timeout reading hello from %s", addr)
                    c.close()
                    continue
                ident = N4Packet.dec_hello(hello)
                if ident is None:
                    logger.warning("Invalid hello packet from %s, ignored", addr)
                    c.close()
                    continue
                if ident == self.ident:
                    # 把 socket 转为阻塞并保存（保持 peername）
                    c.setblocking(True)
                    self.conn.append(c)
                    logger.info("Client accepted (%d/%d)", len(self.conn), max_clients)
                else:
                    logger.info("Identifier mismatch from %s, ignored", addr)
                    c.close()
            except Exception as e:
                logger.exception("Error while accepting client: %s", e)

    def serve(self, allow_cross_ip: bool = False) -> None:
        try:
            self._init_sock()
            self._wait_clients()
            # 清理 UDP 缓冲区，避免旧包干扰
            self._clear_udp_buff()

            # 通知两个 TCP 客户端：ready
            ready_pkt = N4Packet.ready()
            for s in self.conn:
                try:
                    s.sendall(ready_pkt)
                except Exception:
                    pass

            ok = [False, False]  # whether each peer info already sent
            try:
                # 主循环：监听 UDP，等待来自客户端的 exchange 包并把对方地址通知另一端
                while True:
                    data, addr = self.udp_sock.recvfrom(65535)
                    if len(data) != N4Packet.SIZE:
                        logger.debug("忽略不合长度 UDP 包来自 %s:%s len=%d", addr[0], addr[1], len(data))
                        continue
                    recv_ident = N4Packet.dec_exchange(data)
                    if recv_ident is None:
                        logger.debug("忽略非 exchange 包来自 %s:%s", addr[0], addr[1])
                        continue
                    # 将来自 addr 的 peerinfo 发给另一端（按 peer IP 匹配）
                    for idx, s in enumerate(self.conn):
                        if not ok[idx] and self._sock_same_peer_ip(s, addr, allow_cross_ip=allow_cross_ip):
                            other_idx = 1 - idx
                            peerinfo_pkt = N4Packet.peerinfo(addr)
                            try:
                                self.conn[other_idx].sendall(peerinfo_pkt)
                                ok[idx] = True
                                logger.info("已将 %s:%d 通知给 conn[%d]", addr[0], addr[1], other_idx)
                            except Exception:
                                logger.exception("发送 peerinfo 失败")
                    if all(ok):
                        logger.info("已完成双方地址交换")
                        break
            except Exception as e:
                logger.exception("serve loop error: %s", e)
            finally:
                self._clear_udp_buff()
        finally:
            self._close_all_sock()

# ---------- client ----------
class N4Client:
    def __init__(
        self,
        ident: bytes,
        server_host: str,
        server_port: int,
        src_port_start: int,
        src_port_count: int,
        peer_port_offset: int,
        allow_cross_ip: bool,
        tcp_timeout: int = 10
    ) -> None:
        self.ident = ident
        self.server_host = server_host
        self.server_port = server_port
        self.src_port_start = src_port_start
        self.src_port_count = src_port_count
        self.peer_port_offset = peer_port_offset
        self.allow_cross_ip = allow_cross_ip
        self.tcp_timeout = tcp_timeout

        self.tcp_sock: Optional[socket.socket] = None
        self.pool: List[socket.socket] = []

    def _init_sock(self) -> None:
        # TCP control socket
        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_sock.settimeout(self.tcp_timeout)
        self.tcp_sock.connect((self.server_host, self.server_port))
        # UDP pool: bind to a sequence of local ports (或 0 表示任意可用端口)
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

    def _close_all_sock(self) -> None:
        if self.tcp_sock:
            try:
                self.tcp_sock.close()
            except Exception:
                pass
            self.tcp_sock = None
        while self.pool:
            s = self.pool.pop()
            try:
                s.close()
            except Exception:
                pass

    def punch(self, wait: int = 10) -> Tuple[Tuple[str, int], int]:
        """
        尝试打洞，返回 (recv_peer, local_src_port)
        如果失败会抛出 PunchFailure
        """
        try:
            self._init_sock()

            # 发送 hello 到服务器（TCP）
            hello_pkt = N4Packet.hello(self.ident)
            self.tcp_sock.sendall(hello_pkt)
            logger.info("<= Hello (sent)")

            # 等待 server ready
            try:
                ready_pkt = self.tcp_sock.recv(N4Packet.SIZE)
            except socket.timeout:
                raise InvalidPacket("Timeout waiting for ready from server")
            if not N4Packet.dec_ready(ready_pkt):
                raise InvalidPacket("Invalid ready packet from server")
            logger.info("=> Ready (received)")

            # 通过 UDP 向 server 发送 exchange（多次发送以增加成功率）
            exchg_pkt = N4Packet.exchange(self.ident)
            for _ in range(3):
                try:
                    self.pool[0].sendto(exchg_pkt, (self.server_host, self.server_port))
                except Exception:
                    pass
                time.sleep(0.05)

            logger.info("<= Exchange (sent)")

            # 从 TCP 等待 peerinfo
            try:
                pinfo_pkt = self.tcp_sock.recv(N4Packet.SIZE)
            except socket.timeout:
                raise InvalidPacket("Timeout waiting for peerinfo from server")
            peer = N4Packet.dec_peerinfo(pinfo_pkt)
            if not peer:
                raise InvalidPacket("Invalid peerinfo packet")
            peer_ip, peer_port = peer
            target = (peer_ip, peer_port + self.peer_port_offset)
            logger.info("=> Peer from server: %s:%d", peer_ip, peer_port)
            logger.info("   [ target -> %s:%d ]", target[0], target[1])

            # 构造 Punch 包，向目标发送多次
            punch_pkt = N4Packet.punch(self.ident)
            for _ in range(5):
                for s in self.pool:
                    try:
                        s.sendto(punch_pkt, target)
                    except Exception:
                        pass
                time.sleep(0.05)

            logger.info("<= Punch (to target) sent")

            # 等待来自对端的 punch 包
            deadline = time.time() + wait
            recv_peer: Optional[Tuple[str, int]] = None
            recv_sock: Optional[socket.socket] = None
            while time.time() < deadline:
                rlist, _, _ = select.select(self.pool, [], [], max(0.0, deadline - time.time()))
                if not rlist:
                    continue
                for s in rlist:
                    try:
                        data, addr = s.recvfrom(65535)
                    except socket.timeout:
                        continue
                    except Exception:
                        continue
                    # 仅接受指定长度的 punch 包
                    if len(data) != N4Packet.SIZE:
                        logger.debug("忽略非 N4 包 len=%d 来自 %s:%d", len(data), addr[0], addr[1])
                        continue
                    dec = N4Packet.dec_punch(data)
                    if dec is None:
                        logger.debug("忽略非 punch 包 来自 %s:%d", addr[0], addr[1])
                        continue
                    # 验证来源 IP 或在允许交叉 IP 时接受
                    if addr[0] == peer_ip or self.allow_cross_ip:
                        recv_peer = addr
                        recv_sock = s
                        break
                if recv_peer:
                    break

            if not recv_peer or not recv_sock:
                raise PunchFailure("Timeout waiting for peer punch")

            logger.info("=> Received punch from peer %s:%d", recv_peer[0], recv_peer[1])

            # 为降低丢包再回发多次
            for _ in range(6):
                try:
                    recv_sock.sendto(punch_pkt, recv_peer)
                except Exception:
                    pass
                time.sleep(0.05)

            local_port = recv_sock.getsockname()[1]
            logger.info("Local UDP port used: %d", local_port)

            return recv_peer, local_port
        finally:
            self._close_all_sock()

# ---------- CLI / main ----------
def ident_t(a: str) -> bytes:
    # 保证返回 6 字节 ASCII（左填充空格）
    b = str(a).encode("ascii", "ignore")[:6]
    if len(b) < 6:
        b = b.ljust(6, b' ')
    if len(b) != 6:
        raise argparse.ArgumentTypeError("identifier must be up to 6 ascii chars")
    return b

def srv_main(args: argparse.Namespace) -> None:
    ident = args.a
    port = args.l
    allow_cross_ip = args.x
    while True:
        try:
            n4s = N4Server(ident, port, accept_timeout=60)
            n4s.serve(allow_cross_ip=allow_cross_ip)
        except TimeoutError:
            logger.warning("等待客户超时，服务器重启监听")
            time.sleep(1)
            continue
        except KeyboardInterrupt:
            logger.info("服务器手动停止")
            break
        except Exception:
            logger.exception("服务器异常，重启")
            time.sleep(1)
            continue

def cli_main(args: argparse.Namespace) -> None:
    ident = args.a
    server_host = args.h
    server_port = args.p
    port = args.b
    count = args.n
    offset = args.o
    allow_cross_ip = args.x

    while True:
        try:
            n4c = N4Client(
                ident=ident,
                server_host=server_host,
                server_port=server_port,
                src_port_start=port,
                src_port_count=count,
                peer_port_offset=offset,
                allow_cross_ip=allow_cross_ip
            )
            logger.info("==================")
            logger.info("Source port range hint: %d - %d", port, (port + max(0, count-1)))
            peer, src_port = n4c.punch(wait=10)
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
            logger.error("协议错误: %s", e)
            break
        except KeyboardInterrupt:
            logger.info("客户端手动停止")
            break
        except Exception:
            logger.exception("未知错误")
            break

def main() -> None:
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
