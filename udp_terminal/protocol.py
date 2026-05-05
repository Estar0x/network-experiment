"""UDP 远程终端实验的报文格式和可靠传输工具。"""

from __future__ import annotations

import socket
import struct
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable, Deque, Dict, Optional, Tuple

# 一、协议格式
# UDP 数据报首部固定 13 字节，包含魔数、报文类型、序列号、载荷长度和客户端 ID。
MAGIC = 0x5554
# 报文类型。命令/输出/ACK/心跳报文
TYPE_COMMAND = 0x01
TYPE_OUTPUT = 0x02
TYPE_ACK = 0x03
TYPE_HEARTBEAT = 0x04

# 固定应用层首部：
# magic(2) + type(1) + seq(4) + payload_len(2) + client_id(4) = 13 bytes.
HEADER = struct.Struct("!HBIHI")

# TYPE_COMMAND 报文中携带的业务子类型。
CMD_INPUT = b"I"
CMD_WINDOW = b"W"
CMD_CLOSE = b"X"
# TYPE_OUTPUT 报文中携带的业务子类型。
OUT_DATA = b"D"
OUT_MESSAGE = b"M"
OUT_END = b"E"

# ACK 载荷保存对端通告的剩余接收窗口。
ACK_WINDOW = struct.Struct("!H")
HEADER_SIZE = HEADER.size
MAX_DATAGRAM = 1472
MAX_PAYLOAD = MAX_DATAGRAM - HEADER_SIZE
MAX_SEQ = 0xFFFFFFFF
DEFAULT_WINDOW_SIZE = 8
DEFAULT_RECV_BUFFER = 16

# 三、数据类型
class ProtocolError(ValueError):
    """UDP 数据报不符合自定义协议格式时抛出。"""

# 3.1 数据报解析后的结果
@dataclass(frozen=True)
class Packet:
    """固定首部校验通过后的解码结果。"""

    msg_type: int
    seq: int
    client_id: int
    payload: bytes = b""

# 3.2  ACK 状态
@dataclass(frozen=True)
class AckState:
    """累计确认号，以及对端当前可用的接收窗口。"""

    ack_seq: int
    advertised_window: int

# 二、封包与解包
# 2.1 把字段打包成 UDP 要发送的 bytes
def pack_packet(msg_type: int, seq: int, client_id: int, payload: bytes = b"") -> bytes:
    """按固定首部格式打包一个 UDP 数据报。"""
    if not 0 <= seq <= MAX_SEQ:
        raise ValueError("sequence number must fit in 32 bits")
    if not 0 <= client_id <= MAX_SEQ:
        raise ValueError("client id must fit in 32 bits")
    if len(payload) > MAX_PAYLOAD:
        raise ValueError(f"payload too large: {len(payload)} > {MAX_PAYLOAD}")
    header = HEADER.pack(MAGIC, msg_type, seq, len(payload), client_id)
    return header + payload

# 2.2 把收到的 bytes 解析成 Packet
def unpack_packet(data: bytes) -> Packet:
    """解析并校验一个自定义 UDP 数据报。"""
    if len(data) < HEADER_SIZE:
        raise ProtocolError("packet is shorter than the fixed header")

    magic, msg_type, seq, length, client_id = HEADER.unpack(data[:HEADER_SIZE])
    if magic != MAGIC:
        raise ProtocolError("bad magic")
    if length != len(data) - HEADER_SIZE:
        raise ProtocolError("payload length mismatch")
    if length > MAX_PAYLOAD:
        raise ProtocolError("payload is larger than the safe UDP payload")

    return Packet(msg_type=msg_type, seq=seq, client_id=client_id, payload=data[HEADER_SIZE:])

# 2.3 构造 ACK
def ack_packet(seq: int, client_id: int, advertised_window: int = DEFAULT_WINDOW_SIZE) -> bytes:
    """构造 ACK 报文，首部中的 seq 表示累计确认号。"""
    window = max(0, min(advertised_window, 0xFFFF))
    return pack_packet(TYPE_ACK, seq, client_id, ACK_WINDOW.pack(window))

# 2.4 解析 ACK 确认号和窗口大小
def parse_ack(packet: Packet) -> AckState:
    """从 ACK 报文中取出累计确认号和通告窗口。"""
    if packet.msg_type != TYPE_ACK:
        raise ProtocolError("packet is not an ACK")
    if not packet.payload:
        return AckState(packet.seq, DEFAULT_WINDOW_SIZE)
    if len(packet.payload) != ACK_WINDOW.size:
        raise ProtocolError("bad ACK payload")
    (window,) = ACK_WINDOW.unpack(packet.payload)
    return AckState(packet.seq, window)


@dataclass
class _SendItem:
    """一个等待发送或等待确认的可靠报文。

    Go-Back-N 需要在超时时重传整个未确认窗口，所以发出去的报文不能丢掉，
    必须暂存在 _outstanding 中，直到收到累计 ACK 后才能移除。
    """

    msg_type: int
    seq: int
    payload: bytes
    attempts: int = 0

# 四、发送端
class GoBackNSender:
    """带滑动窗口流量控制的 Go-Back-N 发送端。

    发送端允许多个未确认报文同时在网络中传输。ACK 携带累计确认号和接收窗口；
    当最早的未确认报文超时时，发送端会重传整个未确认窗口，这正是
    Go-Back-N ARQ 的核心行为。
    """

    def __init__(
        self,
        sock: socket.socket,
        address_getter: Callable[[], Optional[Tuple[str, int]]],
        client_id: int,
        *,
        max_window: int = DEFAULT_WINDOW_SIZE,
        ack_timeout: float = 1.0,
        retries: int = 5,
        max_queue: int = 256,
        on_failure: Optional[Callable[[str], None]] = None,
        name: str = "sender",
    ) -> None:
        # sock 是真正发 UDP 的 socket；address_getter 用来动态取得对端地址。
        # 服务端的客户端地址可能随报文更新，所以这里用回调而不是固定地址。
        self.sock = sock
        self.address_getter = address_getter
        self.client_id = client_id

        # max_window 是本端允许的最大滑动窗口；peer_window 是对端 ACK 中通告的接收窗口。
        # 实际发送窗口会取两者较小值，实现“既不超过本端配置，也不撑爆接收端”。
        self.max_window = max(1, min(max_window, 0xFFFF))
        self.peer_window = self.max_window

        # ack_timeout 控制多久没收到 ACK 就重传；retries 控制最多重传多少轮。
        self.ack_timeout = ack_timeout
        self.retries = retries

        # max_queue 限制本地积压，避免业务层持续写入导致内存无限增长。
        self.max_queue = max(self.max_window, max_queue)
        self.on_failure = on_failure
        self.name = name

        # _next_seq 是下一个要分配的序列号，可靠报文从 1 开始递增。
        self._next_seq = 1

        # _last_ack_seq 记录最近一次收到的累计 ACK。
        # 例如 ACK=5 表示 seq<=5 的报文都已经连续到达对端。
        self._last_ack_seq = 0

        # _queue 保存“还没真正发出去”的报文。
        # _outstanding 保存“已经发出去，但还没有被累计 ACK 确认”的报文。
        self._queue: Deque[_SendItem] = deque()
        self._outstanding: Dict[int, _SendItem] = {}

        # _last_send_time 用于判断未确认窗口是否超时。
        # Go-Back-N 只需要盯住最早未确认报文对应的计时器。
        self._last_send_time: Optional[float] = None
        self._closed = False
        self._failed = False

        # Condition 同时承担“互斥锁”和“线程通知”两个作用。
        # send()/mark_ack()/stop() 会修改共享状态，后台 _run() 会等待这些状态变化。
        self._condition = threading.Condition()

        # 后台线程负责真正发包、等待 ACK、超时重传；业务层调用 send() 只负责入队。
        self._worker = threading.Thread(target=self._run, daemon=True, name=f"{name}-gbn")
        self._worker.start()

    # 把数据放进发送队列
    def send(
        self,
        msg_type: int,
        payload: bytes = b"",
    ) -> bool:
        """把一个非 ACK 可靠报文加入队列，由后台线程按窗口发送。"""
        # ACK 是接收方立即回复的控制报文，不进入可靠发送队列；
        # 如果 ACK 也等待 ACK，就会形成无限确认循环。
        if msg_type == TYPE_ACK:
            raise ValueError("GoBackNSender must not send ACK packets")
        if len(payload) > MAX_PAYLOAD:
            raise ValueError(f"payload too large: {len(payload)} > {MAX_PAYLOAD}")

        with self._condition:
            # 没关闭、没失败但本地积压已满时，需要等待 ACK 释放空间。
            while not self._closed and not self._failed and self._queued_count() >= self.max_queue:
                # wait() 会释放锁并睡眠，收到 ACK 或关闭通知后再醒来重新检查。
                self._condition.wait()

            if self._closed or self._failed:
                # 等待过程中可能被关闭或标记失败，此时不能继续入队。
                return False

            # 每个可靠报文在入队时分配唯一序列号；后续 ACK、去重和重传都依赖这个 seq。
            seq = self._next_seq
            self._next_seq += 1
            self._queue.append(_SendItem(msg_type=msg_type, seq=seq, payload=payload))

            # 唤醒后台线程，让它检查当前窗口是否还能继续发送。
            self._condition.notify_all()
            return True

    # 收到 ACK 后滑动窗口
    def mark_ack(self, ack_seq: int, advertised_window: int) -> None:
        """收到累计 ACK 后滑动发送窗口。"""
        # 对端可能通告很大的窗口，这里限制在本端 max_window 内。
        window = max(0, min(advertised_window, self.max_window))
        with self._condition:
            # 小于 _last_ack_seq 的 ACK 是旧 ACK，说明它已经被更新的 ACK 覆盖，可以忽略。
            if ack_seq < self._last_ack_seq:
                return
            if ack_seq > self._last_ack_seq:
                # 新的累计 ACK 到达，说明发送窗口左边界可以右移。
                self._last_ack_seq = ack_seq
                self.peer_window = window
            else:
                # 相同累计 ACK 可能乱序到达，这里保留最新的空闲窗口信息。
                self.peer_window = max(self.peer_window, window)

            # 累计 ACK 的含义是 seq<=ack_seq 都已经连续到达对端，
            # 因此这些报文可以从未确认窗口 _outstanding 中移除。
            advanced = False
            for seq in list(self._outstanding):
                if seq <= ack_seq:
                    self._outstanding.pop(seq, None)
                    advanced = True
            if advanced:
                # 如果窗口里还有未确认报文，重新从当前时刻开始计时；
                # 如果都确认完了，就清空计时器，等待下一批发送。
                self._last_send_time = time.monotonic() if self._outstanding else None
            self._condition.notify_all()

    def drain(self, timeout: Optional[float] = None) -> bool:
        """等待队列中和窗口内的所有报文都被 ACK 确认。"""
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._condition:
            # _queue 为空表示没有待发送报文；_outstanding 为空表示已发送报文都确认了。
            # 两者都为空时，说明发送端已经完全“排空”。
            while self._queue or self._outstanding:
                if self._failed:
                    return False
                if deadline is None:
                    self._condition.wait()
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            return True

    def stop(self, drain_timeout: float = 0.0) -> None:
        """停止发送线程，可选择短暂等待未确认报文完成。"""
        drained = False
        if drain_timeout > 0:
            drained = self.drain(drain_timeout)
        with self._condition:
            self._closed = True
            if not drained:
                # 如果关闭时不等待或等待失败，就丢弃本地积压，避免退出过程卡住。
                self._queue.clear()
                self._outstanding.clear()
            self._condition.notify_all()
        if threading.current_thread() is not self._worker:
            self._worker.join(timeout=1.0)

    def _queued_count(self) -> int:
        """当前占用本地发送容量的报文数量。"""
        # 待发送报文和未确认报文都会占用本地发送器容量。
        return len(self._queue) + len(self._outstanding)

    def _effective_window(self) -> int:
        """结合对端通告窗口后实际允许使用的发送窗口。"""
        # 本端配置的 max_window 控制“最多能飞多少包”，peer_window 控制“对端还能收多少包”。
        return max(0, min(self.max_window, self.peer_window))

    # 发送和重传
    def _run(self) -> None:
        """后台循环：发送新报文、检测超时并执行重传。"""
        while True:
            # to_send 只保存“本轮需要通过 socket 发出的报文”。
            # 先在锁内决定要发什么，再在锁外真正发 UDP，避免 socket 阻塞影响其他线程处理 ACK。
            to_send: list[_SendItem] = []
            failure_reason: Optional[str] = None

            with self._condition:
                # 已请求关闭，并且没有剩余报文时，后台线程可以退出。
                if self._closed and not self._queue and not self._outstanding:
                    return
                if self._failed:
                    return

                now = time.monotonic()
                effective_window = self._effective_window()

                # 在当前滑动窗口允许的范围内尽量发送新报文。
                while self._queue and len(self._outstanding) < effective_window:
                    # 报文一旦从 _queue 取出，就进入 _outstanding。
                    # 从这一刻开始，它会被 ACK 管理，也可能在超时时被重传。
                    item = self._queue.popleft()
                    item.attempts += 1
                    self._outstanding[item.seq] = item
                    to_send.append(item)

                if to_send:
                    # 本轮发出了新报文，刷新计时器。
                    self._last_send_time = now
                elif self._outstanding and self._last_send_time is not None:
                    # 没有新报文可发，但还有未确认报文，此时检查是否超时。
                    elapsed = now - self._last_send_time
                    if elapsed >= self.ack_timeout:
                        # Go-Back-N 的重传规则：最早报文超时后重传整个未确认窗口。
                        for item in self._outstanding.values():
                            # attempts 统计发送次数：首次发送也算一次，后续每轮重传继续增加。
                            item.attempts += 1
                            if item.attempts > self.retries + 1:
                                failure_reason = (
                                    f"{self.name} gave up after {self.retries} retransmissions "
                                    f"at seq {item.seq}"
                                )
                                break
                        if failure_reason is None:
                            # 不是选择性重传某一个包，而是重传所有未确认报文。
                            to_send = list(self._outstanding.values())
                            self._last_send_time = now
                    else:
                        # 还没到超时时间，后台线程先睡到下一次可能超时的时刻。
                        self._condition.wait(self.ack_timeout - elapsed)
                        continue
                else:
                    # 既没有待发送报文，也没有未确认报文，等待 send() 入队或 stop() 关闭。
                    self._condition.wait()
                    continue

                if failure_reason is not None:
                    # 超过重传次数后标记失败，并唤醒可能正在 send()/drain() 中等待的线程。
                    self._failed = True
                    self._condition.notify_all()

            if failure_reason is not None:
                # 失败回调放在锁外执行，避免回调里再调用其他方法造成死锁。
                if self.on_failure is not None:
                    self.on_failure(failure_reason)
                return

            for item in to_send:
                # 真正的 UDP 发送发生在这里；如果发送失败，_send_item 会设置 _failed。
                if not self._send_item(item):
                    return

    def _send_item(self, item: _SendItem) -> bool:
        """序列化一个待发送项，并通过 UDP 发出。"""
        try:
            # pack_packet 会把 msg_type、seq、client_id、payload_len 等字段写入固定协议头。
            data = pack_packet(item.msg_type, item.seq, self.client_id, item.payload)
            addr = self.address_getter()
            if addr is None:
                self.sock.send(data)
            else:
                self.sock.sendto(data, addr)
            return True
        except OSError as exc:
            reason = f"{self.name} socket send failed: {exc}"
            with self._condition:
                self._failed = True
                self._condition.notify_all()
            if self.on_failure is not None:
                self.on_failure(reason)
            return False

# 五、接收端

class GoBackNReceiver:
    """带有限接收缓冲区的 Go-Back-N 接收端。

    接收端只接受下一个期望序号。更靠后的乱序报文会被丢弃，并重复确认最后一个
    连续到达的报文，等待发送端超时后回退重传。通告窗口等于接收缓冲区中的空闲槽位数。
    """

    def __init__(
        self,
        client_id: int,
        handler: Callable[[Packet], None],
        *,
        max_buffer: int = DEFAULT_RECV_BUFFER,
        window_update: Optional[Callable[[AckState], None]] = None,
        name: str = "receiver",
    ) -> None:
        self.client_id = client_id

        # handler 是业务层处理函数。接收端只把“按序确认过”的报文交给它。
        self.handler = handler

        # max_buffer 是接收端缓存容量；ACK 中通告的窗口就是剩余缓存槽位。
        self.max_buffer = max(1, min(max_buffer, 0xFFFF))

        # 当接收缓冲区从满变为有空位时，用 window_update 主动发送窗口更新 ACK。
        self.window_update = window_update
        self.name = name

        # _expected_seq 表示当前只接受哪个序号。
        # 如果收到更大的序号，说明中间有包缺失，Go-Back-N 接收端会直接丢弃。
        self._expected_seq = 1

        # _last_ack_seq 是最后一个连续收到的序号，返回 ACK 时使用它。
        self._last_ack_seq = 0

        # _queue 保存已经按序接收、等待交给业务层处理的报文。
        # 网络接收线程只负责 accept()，业务处理在后台投递线程中做，避免阻塞收包。
        self._queue: Deque[Packet] = deque()
        self._closed = False
        self._condition = threading.Condition()
        self._worker = threading.Thread(target=self._run, daemon=True, name=f"{name}-deliver")
        self._worker.start()

    def accept(self, packet: Packet) -> AckState:
        """只接收下一个期望序号的报文，并返回应发送的 ACK 状态。"""
        with self._condition:
            if self._closed:
                # 接收端关闭后通告窗口为 0，表示不再接收新数据。
                return AckState(self._last_ack_seq, 0)

            if packet.seq == self._expected_seq and len(self._queue) < self.max_buffer:
                # 只有“正好等着的序号”才会进入接收队列。
                # 进入队列后，期望序号加 1，累计 ACK 也前进到当前报文。
                self._queue.append(packet)
                self._expected_seq += 1
                self._last_ack_seq = packet.seq
                self._condition.notify_all()

            # 如果是重复包、旧包、乱序包，或者缓冲区已满，都不会更新 _last_ack_seq。
            # 返回旧 ACK 可让发送端知道：接收端仍然只连续收到这里为止。
            return AckState(self._last_ack_seq, self._free_slots())

    def stop(self) -> None:
        """在已接收报文处理完成后停止投递线程。"""
        with self._condition:
            self._closed = True
            # 唤醒 _run()，让它在队列处理完后退出。
            self._condition.notify_all()
        if threading.current_thread() is not self._worker:
            self._worker.join(timeout=1.0)

    def _free_slots(self) -> int:
        """接收缓冲区中剩余的报文槽位数。"""
        # 这个值会写入 ACK 的 advertised_window，用于发送端流量控制。
        return self.max_buffer - len(self._queue)

    def _run(self) -> None:
        """按接收顺序把已接收报文投递给业务处理函数。"""
        while True:
            update: Optional[AckState] = None

            with self._condition:
                # 队列为空时，投递线程等待 accept() 放入新报文。
                while not self._closed and not self._queue:
                    self._condition.wait()
                if self._closed and not self._queue:
                    return

                # 如果取出报文前队列是满的，那么取出后就释放了窗口。
                # 此时需要主动通告新的窗口，避免发送端因为看到 0 窗口而停住。
                was_full = len(self._queue) >= self.max_buffer
                packet = self._queue.popleft()
                if was_full:
                    update = AckState(self._last_ack_seq, self._free_slots())
                self._condition.notify_all()

            if update is not None and self.window_update is not None:
                # 窗口更新 ACK 放在锁外发送，避免 socket 操作阻塞接收端内部状态。
                self.window_update(update)

            try:
                # 只有通过 Go-Back-N 顺序检查的报文才会交给业务层。
                self.handler(packet)
            except Exception:
                # 单个业务处理异常不应杀死 UDP 接收循环。
                continue
