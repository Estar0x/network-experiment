#!/usr/bin/env python3
"""UDP 远程终端客户端。"""

from __future__ import annotations

import argparse
import os
import random
import select
import shutil
import signal
import socket
import struct
import sys
import termios
import threading
import tty
from contextlib import contextmanager
from typing import Optional, Tuple

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
    Packet,
    TYPE_ACK,
    TYPE_COMMAND,
    TYPE_HEARTBEAT,
    TYPE_OUTPUT,
    ack_packet,
    parse_ack,
    unpack_packet,
    ProtocolError,
)

Address = Tuple[str, int]

# 预留 1 字节存放 CMD_INPUT/CMD_WINDOW/CMD_CLOSE 子类型。
INPUT_CHUNK = MAX_PAYLOAD - 1


@contextmanager
def raw_terminal():
    """临时把本地终端切到 raw 模式，实现按键级输入转发。"""
    fd = sys.stdin.fileno()
    old_attrs = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        yield
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_attrs)


class UDPRemoteTerminalClient:
    """UDP 远程终端的客户端侧实现。"""

    def __init__(
        self,
        server: Address,
        *,
        client_id: Optional[int],
        ack_timeout: float,
        retries: int,
        heartbeat_interval: float,
        window_size: int,
        recv_buffer: int,
        sender_queue: int,
    ) -> None:
        self.server = server
        self.client_id = client_id if client_id is not None else random.randrange(1, 0xFFFFFFFF)
        self.heartbeat_interval = heartbeat_interval
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("", 0))
        self.sock.settimeout(0.5)
        self.failed_event = threading.Event()

        # 客户端到服务端的报文共用一个 Go-Back-N 发送端：输入、窗口大小、关闭请求和心跳都需要 ACK。
        self.sender = GoBackNSender(
            self.sock,
            lambda: self.server,
            self.client_id,
            max_window=window_size,
            ack_timeout=ack_timeout,
            retries=retries,
            max_queue=sender_queue,
            on_failure=self._sender_failed,
            name=f"client-input-{self.client_id}",
        )

        # 服务端输出只按序接收，确认顺序正确后再打印到本地终端。
        self.output_receiver = GoBackNReceiver(
            self.client_id,
            self._deliver_output,
            max_buffer=recv_buffer,
            window_update=self._send_ack_state,
            name=f"client-output-{self.client_id}",
        )
        self.stop_event = threading.Event()
        self.receiver = threading.Thread(target=self._receive_loop, daemon=True)
        self.heartbeat = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self.resize_event = threading.Event()

    def _sender_failed(self, reason: str) -> None:
        """可靠发送放弃重传后停止客户端。"""
        self.failed_event.set()
        print(f"\r\n[client] {reason}\r\n", file=sys.stderr)
        self.stop_event.set()

    def _send_ack_state(self, state: AckState) -> None:
        """确认服务端输出，并通告本地接收缓冲区剩余空间。"""
        try:
            self.sock.sendto(ack_packet(state.ack_seq, self.client_id, state.advertised_window), self.server)
        except OSError:
            pass

    def start(self) -> None:
        """启动后台接收线程和心跳线程。"""
        self.receiver.start()
        self.heartbeat.start()
        self.send_window_size()

    def close(self) -> None:
        """请求远程 shell 关闭，并停止本地后台线程。"""
        send_close = not self.stop_event.is_set()
        if send_close:
            self._send_control(CMD_CLOSE)
            self.sender.drain(timeout=2.0)
        self.stop_event.set()
        self.sender.stop()
        self.output_receiver.stop()
        try:
            self.sock.close()
        except OSError:
            pass

    def run_interactive(self) -> int:
        """运行完整交互模式：本地按键会变成远程终端输入。"""
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            print("interactive mode requires a real terminal", file=sys.stderr)
            return 2

        print(f"Connected to {self.server[0]}:{self.server[1]} as client {self.client_id}.")
        print("Press Ctrl-] to close the client.")
        self.start()

        old_winch = signal.getsignal(signal.SIGWINCH)

        def on_winch(_signum: int, _frame: object) -> None:
            self.resize_event.set()

        # 本地窗口大小变化需要转发给服务端，方便全屏程序重新绘制界面。
        signal.signal(signal.SIGWINCH, on_winch)

        try:
            with raw_terminal():
                while not self.stop_event.is_set():
                    readable, _, _ = select.select([sys.stdin], [], [], 0.2)
                    if self.resize_event.is_set():
                        self.resize_event.clear()
                        self.send_window_size()
                    if not readable:
                        continue
                    data = os.read(sys.stdin.fileno(), 512)
                    if not data:
                        break
                    if b"\x1d" in data:
                        # Ctrl-] 是本地退出键；Ctrl+C 不在这里拦截，而是透明发送给远程 PTY。
                        before, _, _ = data.partition(b"\x1d")
                        if before:
                            self.send_input(before)
                        break
                    self.send_input(data)
        finally:
            signal.signal(signal.SIGWINCH, old_winch)
            self.close()
        return 0

    def run_command(self, command: str, timeout: float) -> int:
        """用于自动化测试的便捷模式：执行一条命令后退出。"""
        self.start()
        self.send_input(command.encode("utf-8") + b"\nexit\n")
        finished = self.stop_event.wait(timeout)
        self.close()
        return 0 if finished and not self.failed_event.is_set() else 1

    def send_input(self, data: bytes) -> bool:
        """把终端输入切分成不会超过 UDP 安全载荷的片段。"""
        ok = True
        for start in range(0, len(data), INPUT_CHUNK):
            if not self._send_control(CMD_INPUT, data[start : start + INPUT_CHUNK]):
                ok = False
                break
        return ok

    def send_window_size(self) -> bool:
        """把当前终端行列数发送给服务端 PTY。"""
        size = shutil.get_terminal_size(fallback=(80, 24))
        payload = struct.pack("!HH", size.lines, size.columns)
        return self._send_control(CMD_WINDOW, payload)

    def _send_control(self, subtype: bytes, body: bytes = b"") -> bool:
        """通过可靠发送端排队发送一个命令报文。"""
        payload = subtype + body
        ok = self.sender.send(TYPE_COMMAND, payload)
        if not ok:
            print("\r\n[client] server did not ACK after retries\r\n", file=sys.stderr)
            self.failed_event.set()
            self.stop_event.set()
        return ok

    def _heartbeat_loop(self) -> None:
        """定期发送心跳包，让服务端知道客户端仍在线。"""
        while not self.stop_event.wait(self.heartbeat_interval):
            ok = self.sender.send(TYPE_HEARTBEAT)
            if not ok:
                print("\r\n[client] heartbeat timeout\r\n", file=sys.stderr)
                self.failed_event.set()
                self.stop_event.set()
                return

    def _receive_loop(self) -> None:
        """接收 UDP 报文，并分流处理 ACK 或远程输出。"""
        while not self.stop_event.is_set():
            try:
                data, _addr = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                packet = unpack_packet(data)
            except ProtocolError:
                continue
            if packet.client_id != self.client_id:
                continue

            if packet.msg_type == TYPE_ACK:
                # ACK 用来推动客户端到服务端方向的发送窗口前移。
                try:
                    ack = parse_ack(packet)
                except ProtocolError:
                    continue
                self.sender.mark_ack(ack.ack_seq, ack.advertised_window)
                continue

            if packet.msg_type != TYPE_OUTPUT:
                continue

            # 输出报文先经过 Go-Back-N 接收端，确认按序后再打印。
            ack = self.output_receiver.accept(packet)
            self._send_ack_state(ack)

    def _deliver_output(self, packet: Packet) -> None:
        """把已经按序接收的服务端输出打印到本地终端。"""
        payload = packet.payload
        if not payload:
            return
        subtype, body = payload[:1], payload[1:]
        if subtype == OUT_DATA:
            os.write(sys.stdout.fileno(), body)
        elif subtype == OUT_MESSAGE:
            os.write(sys.stdout.fileno(), body)
        elif subtype == OUT_END:
            os.write(sys.stdout.fileno(), body)
            self.stop_event.set()


def parse_args() -> argparse.Namespace:
    """解析交互模式和命令模式使用的命令行参数。"""
    parser = argparse.ArgumentParser(description="UDP remote terminal client")
    parser.add_argument("host", help="server IP or host")
    parser.add_argument("port", type=int, help="server UDP port")
    parser.add_argument("--client-id", type=lambda value: int(value, 0), help="32-bit client id")
    parser.add_argument("--ack-timeout", type=float, default=1.0, help="seconds before retransmit")
    parser.add_argument("--retries", type=int, default=5, help="retransmission attempts")
    parser.add_argument("--window-size", type=int, default=DEFAULT_WINDOW_SIZE, help="Go-Back-N send window")
    parser.add_argument("--recv-buffer", type=int, default=DEFAULT_RECV_BUFFER, help="receive buffer packets")
    parser.add_argument("--sender-queue", type=int, default=256, help="maximum queued packets")
    parser.add_argument("--heartbeat-interval", type=float, default=5.0, help="heartbeat interval")
    parser.add_argument("--command", help="run one command, then exit the remote shell")
    parser.add_argument("--timeout", type=float, default=8.0, help="timeout for --command mode")
    return parser.parse_args()


def main() -> int:
    """程序入口：创建客户端并选择交互模式或命令模式。"""
    if os.name != "posix":
        print("This client uses POSIX terminal control and requires Linux/macOS.", file=sys.stderr)
        return 2

    args = parse_args()
    client = UDPRemoteTerminalClient(
        (args.host, args.port),
        client_id=args.client_id,
        ack_timeout=args.ack_timeout,
        retries=args.retries,
        heartbeat_interval=args.heartbeat_interval,
        window_size=args.window_size,
        recv_buffer=args.recv_buffer,
        sender_queue=args.sender_queue,
    )
    try:
        if args.command:
            return client.run_command(args.command, args.timeout)
        return client.run_interactive()
    except KeyboardInterrupt:
        client.close()
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
