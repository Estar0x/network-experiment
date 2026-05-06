#!/usr/bin/env python3
"""UDP 远程终端服务端。

服务端为每个 client_id 维护一个基于 PTY 的 shell。客户端输入、窗口大小更新、
心跳包以及服务端输出都使用 udp_terminal.protocol 中定义的自定义 UDP 首部。
"""

from __future__ import annotations

import argparse
import errno
import fcntl
import os
import pty
import signal
import socket
import struct
import sys
import termios
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from udp_terminal.protocol import (
    CMD_CLOSE,
    CMD_INPUT,
    CMD_WINDOW,
    DEFAULT_RECV_BUFFER,
    DEFAULT_WINDOW_SIZE,
    AckState,
    GoBackNReceiver,
    GoBackNSender,
    MAX_PAYLOAD,
    OUT_DATA,
    OUT_END,
    OUT_MESSAGE,
    TYPE_ACK,
    TYPE_COMMAND,
    TYPE_HEARTBEAT,
    TYPE_OUTPUT,
    Packet,
    ack_packet,
    parse_ack,
    unpack_packet,
    ProtocolError,
)

Address = Tuple[str, int]

# 控制每个 UDP 载荷低于常见以太网 MTU，避免 IP 分片；额外预留 1 字节存放输出子类型。
OUTPUT_CHUNK = min(1024, MAX_PAYLOAD - 1)


@dataclass
class ClientSession:
    """一个逻辑远程终端客户端拥有的全部状态。"""

    client_id: int
    address: Address
    server: "UDPRemoteTerminalServer"
    last_seen: float = field(default_factory=time.monotonic)
    rows: int = 24
    cols: int = 80
    pid: Optional[int] = None
    master_fd: Optional[int] = None
    reader: Optional[threading.Thread] = None
    output_sender: GoBackNSender = field(init=False)
    incoming_receiver: GoBackNReceiver = field(init=False)
    lock: threading.RLock = field(default_factory=threading.RLock)
    closed: bool = False

    # 创建可靠传输组件
    def __post_init__(self) -> None:
        # 两个方向各有一个可靠传输对象：客户端输入按序接收，服务端输出按滑动窗口发送。
        self.output_sender = GoBackNSender(
            self.server.sock,
            lambda: self.address,
            self.client_id,
            max_window=self.server.window_size,
            ack_timeout=self.server.ack_timeout,
            retries=self.server.retries,
            max_queue=self.server.sender_queue,
            on_failure=self._sender_failed,
            name=f"server-output-{self.client_id}",
        )
        self.incoming_receiver = GoBackNReceiver(
            self.client_id,
            self._deliver_incoming,
            max_buffer=self.server.recv_buffer,
            window_update=self._send_ack_state,
            name=f"server-input-{self.client_id}",
        )

    def _sender_failed(self, reason: str) -> None:
        """记录服务端可靠输出发送失败的原因。"""
        self.server.log(f"client {self.client_id} output sender failed: {reason}")

    def _send_ack_state(self, state: AckState) -> None:
        """回复累计 ACK，并携带当前接收窗口通告。"""
        try:
            self.server.sock.sendto(
                ack_packet(state.ack_seq, self.client_id, state.advertised_window),
                self.address,
            )
        except OSError as exc:
            self.server.log(f"client {self.client_id} ACK send failed: {exc}")

    # 创建 PTY shell
    def ensure_shell(self) -> None:
        """首次收到客户端输入时创建对应的 PTY shell。"""
        with self.lock:
            if self.pid is not None and self.master_fd is not None and not self.closed:
                return

            shell = os.environ.get("SHELL") or "/bin/sh"
            env = os.environ.copy()
            env.setdefault("TERM", "xterm-256color")
            env.setdefault("LANG", "C.UTF-8")

            # pty.fork() 会给子进程分配真实终端，因此 Ctrl+C、退格、top/vim 和 ANSI 刷新都能正常工作。
            pid, fd = pty.fork()
            if pid == 0:
                argv = [shell, "-i"]
                try:
                    os.execvpe(shell, argv, env)
                except Exception as exc:  # pragma: no cover - 子进程会立刻退出。
                    os.write(2, f"exec failed: {exc}\n".encode("utf-8", "replace"))
                    os._exit(127)

            self.pid = pid
            self.master_fd = fd
            self.closed = False
            self.apply_window_size(self.rows, self.cols)
            self.reader = threading.Thread(target=self._read_pty_output, daemon=True)
            self.reader.start()
            self.server.log(f"client {self.client_id} shell started with pid {pid}")

    def apply_window_size(self, rows: int, cols: int) -> None:
        """把客户端终端大小同步到服务端 PTY。"""
        self.rows = max(1, min(rows, 500))
        self.cols = max(1, min(cols, 500))
        if self.master_fd is None:
            return
        size = struct.pack("HHHH", self.rows, self.cols, 0, 0)
        fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, size)

    # 把客户端键盘输入写进远程 shell
    def write_input(self, data: bytes) -> None:
        """把已经按序确认的客户端输入写入 PTY。"""
        self.ensure_shell()
        if not data or self.master_fd is None:
            return
        try:
            os.write(self.master_fd, data)
        except OSError as exc:
            self.server.log(f"client {self.client_id} input write failed: {exc}")

    def send_message(self, text: str) -> None:
        """向客户端发送一条简短的终端状态消息。"""
        self._send_output(OUT_MESSAGE + text.encode("utf-8", "replace"))

    def close(self, reason: str = "session closed") -> None:
        """关闭 PTY 会话，并通知客户端。"""
        with self.lock:
            if self.closed:
                return
            self.closed = True
            pid = self.pid
            fd = self.master_fd
            self.pid = None
            self.master_fd = None

        if pid is not None:
            try:
                os.killpg(os.getpgid(pid), signal.SIGHUP)
            except ProcessLookupError:
                pass
            except OSError as exc:
                self.server.log(f"client {self.client_id} kill failed: {exc}")

        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass

        self._send_output(OUT_END + reason.encode("utf-8", "replace"))
        self.output_sender.stop(drain_timeout=2.0)
        self.incoming_receiver.stop()
        self.server.forget_session(self)

    def _send_output(self, payload: bytes) -> bool:
        """把一个输出报文加入可靠滑动窗口发送队列。"""
        return self.output_sender.send(TYPE_OUTPUT, payload)

    def _deliver_incoming(self, packet: Packet) -> None:
        """处理已经被 Go-Back-N 按序接收的业务报文。"""
        self.last_seen = time.monotonic()
        if packet.msg_type == TYPE_HEARTBEAT:
            return
        if packet.msg_type == TYPE_COMMAND:
            self._handle_command_packet(packet)

    # 读远程 shell 的输出，并发送回客户端
    def _read_pty_output(self) -> None:
        """持续读取远程 shell 输出，并可靠发送回客户端。"""
        fd = self.master_fd
        if fd is None:
            return

        try:
            while True:
                try:
                    data = os.read(fd, OUTPUT_CHUNK)
                except OSError as exc:
                    if exc.errno in (errno.EIO, errno.EBADF):
                        break
                    raise
                if not data:
                    break
                if not self._send_output(OUT_DATA + data):
                    self.server.log(f"client {self.client_id} stopped ACKing output")
                    break
        except Exception as exc:
            self.server.log(f"client {self.client_id} output reader failed: {exc}")
        finally:
            with self.lock:
                pid = self.pid
                was_closed = self.closed
                self.pid = None
                self.master_fd = None
                self.closed = True
            if pid is not None:
                try:
                    os.waitpid(pid, 0)
                except ChildProcessError:
                    pass
            if not was_closed:
                self._send_output(OUT_END + b"remote shell exited\r\n")
                self.output_sender.drain(timeout=2.0)
            self.output_sender.stop()
            self.incoming_receiver.stop()
            self.server.forget_session(self)
            self.server.log(f"client {self.client_id} shell exited")

    # 处理命令报文
    def _handle_command_packet(self, packet: Packet) -> None:
        """分发 TYPE_COMMAND 报文中携带的命令子类型。"""
        payload = packet.payload
        if not payload:
            return
        subtype, body = payload[:1], payload[1:]

        if subtype == CMD_INPUT:
            self.write_input(body)
        elif subtype == CMD_WINDOW:
            if len(body) != 4:
                self.send_message("bad window-size packet\r\n")
                return
            rows, cols = struct.unpack("!HH", body)
            self.apply_window_size(rows, cols)
            self.ensure_shell()
        elif subtype == CMD_CLOSE:
            self.close("client closed the terminal\r\n")
        else:
            self.send_message(f"unknown command subtype {subtype!r}\r\n")


class UDPRemoteTerminalServer:
    """把多个客户端 ID 复用到独立会话上的 UDP 服务端。"""

    # 服务端组件
    def __init__(
        self,
        host: str,
        port: int,
        *,
        ack_timeout: float,
        retries: int,
        window_size: int,
        recv_buffer: int,
        sender_queue: int,
        offline_timeout: float,
        verbose: bool = False,
    ) -> None:
        self.host = host
        self.port = port
        self.ack_timeout = ack_timeout
        self.retries = retries
        self.window_size = window_size
        self.recv_buffer = recv_buffer
        self.sender_queue = sender_queue
        self.offline_timeout = offline_timeout
        self.verbose = verbose

        # 服务端接收循环和各客户端发送线程共用一个 UDP socket；
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.sock.settimeout(0.5)
        self.clients: Dict[int, ClientSession] = {}
        self.clients_lock = threading.RLock()
        self.stop_event = threading.Event()

    def log(self, message: str) -> None:
        """仅在 verbose 模式下打印服务端诊断信息。"""
        if self.verbose:
            print(f"[server] {message}", file=sys.stderr, flush=True)

    # 服务段主循环
    def serve_forever(self) -> None:
        """主接收循环：解析数据报，并定期清理超时客户端。"""
        print(f"UDP terminal server listening on {self.host}:{self.port}", flush=True)
        while not self.stop_event.is_set():
            try:
                data, addr = self.sock.recvfrom(2048)
            except socket.timeout:
                self._sweep_offline_clients()
                continue
            except OSError:
                break
            self._handle_datagram(data, addr)

    def shutdown(self) -> None:
        """停止服务端，并关闭所有活跃客户端会话。"""
        self.stop_event.set()
        with self.clients_lock:
            sessions = list(self.clients.values())
            self.clients.clear()
        for session in sessions:
            session.close("server shutdown\r\n")
        self.sock.close()

    def forget_session(self, session: ClientSession) -> None:
        """仅当传入对象仍是当前会话时，才从会话表中移除它。"""
        with self.clients_lock:
            if self.clients.get(session.client_id) is session:
                self.clients.pop(session.client_id, None)

    def _handle_datagram(self, data: bytes, addr: Address) -> None:
        """校验一个 UDP 数据报，并路由到 ACK 或输入处理逻辑。"""
        try:
            packet = unpack_packet(data)
        except ProtocolError:
            self.log(f"drop illegal datagram from {addr}")
            return

        if packet.msg_type == TYPE_ACK:
            # ACK 用来推动服务端到客户端方向的输出窗口前移。
            session = self._find_session(packet.client_id)
            if session is None:
                return
            try:
                ack = parse_ack(packet)
            except ProtocolError:
                return
            session.output_sender.mark_ack(ack.ack_seq, ack.advertised_window)
            return

        if packet.msg_type not in (TYPE_COMMAND, TYPE_HEARTBEAT):
            self.log(f"drop unsupported packet type {packet.msg_type} from {addr}")
            return

        session = self._get_session(packet.client_id, addr)
        session.address = addr
        session.last_seen = time.monotonic()

        # 非 ACK 报文先经过 Go-Back-N 接收端，避免重复、过期、乱序输入被业务层执行。
        ack = session.incoming_receiver.accept(packet)
        session._send_ack_state(ack)

    # 根据 client_id 找会话，没有就创建
    def _get_session(self, client_id: int, addr: Address) -> ClientSession:
        """获取指定客户端 ID 的会话，不存在时创建新会话。"""
        with self.clients_lock:
            session = self.clients.get(client_id)
            if session is None:
                session = ClientSession(client_id=client_id, address=addr, server=self)
                self.clients[client_id] = session
                self.log(f"client {client_id} registered from {addr[0]}:{addr[1]}")
            return session

    def _find_session(self, client_id: int) -> Optional[ClientSession]:
        """只查找会话，不自动创建新会话。"""
        with self.clients_lock:
            return self.clients.get(client_id)

    def _sweep_offline_clients(self) -> None:
        """关闭长时间没有发送心跳的会话。"""
        now = time.monotonic()
        expired = []
        with self.clients_lock:
            for client_id, session in self.clients.items():
                if now - session.last_seen > self.offline_timeout:
                    expired.append(session)
            for session in expired:
                self.clients.pop(session.client_id, None)
        for session in expired:
            self.log(f"client {session.client_id} offline")
            session.close("heartbeat timeout\r\n")


def parse_args() -> argparse.Namespace:
    """解析用于配置 UDP 服务端的命令行参数。"""
    parser = argparse.ArgumentParser(description="UDP remote terminal server")
    parser.add_argument("--host", default="0.0.0.0", help="address to bind")
    parser.add_argument("--port", type=int, default=9000, help="UDP port to bind")
    parser.add_argument("--ack-timeout", type=float, default=1.0, help="seconds before retransmit")
    parser.add_argument("--retries", type=int, default=5, help="retransmission attempts")
    parser.add_argument("--window-size", type=int, default=DEFAULT_WINDOW_SIZE, help="Go-Back-N send window")
    parser.add_argument("--recv-buffer", type=int, default=DEFAULT_RECV_BUFFER, help="receive buffer packets")
    parser.add_argument("--sender-queue", type=int, default=256, help="maximum queued packets per client")
    parser.add_argument("--offline-timeout", type=float, default=20.0, help="heartbeat timeout")
    parser.add_argument("--verbose", action="store_true", help="print debug logs")
    return parser.parse_args()


def main() -> int:
    """程序入口：检查平台、启动服务端并注册退出信号。"""
    if os.name != "posix":
        print("This PTY server requires Linux/macOS. Use a POSIX host for the experiment.", file=sys.stderr)
        return 2

    args = parse_args()
    server = UDPRemoteTerminalServer(
        args.host,
        args.port,
        ack_timeout=args.ack_timeout,
        retries=args.retries,
        window_size=args.window_size,
        recv_buffer=args.recv_buffer,
        sender_queue=args.sender_queue,
        offline_timeout=args.offline_timeout,
        verbose=args.verbose,
    )

    def stop(_signum: int, _frame: object) -> None:
        server.shutdown()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    try:
        server.serve_forever()
    finally:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
