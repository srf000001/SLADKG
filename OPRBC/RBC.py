"""
Bracha Reliable Broadcast (RBC) - Send, Echo, Ready
Asynchronous simulator for reliable broadcast under n ≥ 3f + 1
"""

import asyncio
import random
import time
from collections import defaultdict


class Message:
    def __init__(self, typ, sender, value):
        self.typ = typ  # 'SEND' | 'ECHO' | 'READY'
        self.sender = sender
        self.value = value


class Network:
    def __init__(self, delay_range=(0.01, 0.05)):
        self.nodes = {}
        self.delay_range = delay_range
        self._stop = False

    def register(self, node):
        self.nodes[node.id] = node

    async def send(self, dst_id, msg):
        await asyncio.sleep(random.uniform(*self.delay_range))
        if dst_id in self.nodes:
            await self.nodes[dst_id].inbox.put(msg)

    async def broadcast(self, src_id, msg):
        tasks = []
        for nid in list(self.nodes.keys()):
            tasks.append(asyncio.create_task(self.send(nid, msg)))
        if tasks:
            await asyncio.gather(*tasks)


class Node:
    def __init__(self, node_id, n, f, network, is_sender=False, honest=True):
        self.id = node_id
        self.n = n
        self.f = f
        self.network = network
        self.is_sender = is_sender
        self.honest = honest

        self.inbox = asyncio.Queue()
        self.echo_senders = defaultdict(set)
        self.ready_senders = defaultdict(set)
        self.sent_echo = set()
        self.sent_ready = set()
        self.delivered = None
        self.start_time = None
        self.deliver_time = None

        self.echo_thresh = (self.n + self.f) // 2 + 1
        self.ready_threshold = self.f + 1
        self.deliver_threshold = 2 * self.f + 1

    async def run(self, value_to_send=None, timeout=5.0):
        self.start_time = time.perf_counter()
        if self.is_sender and self.honest and value_to_send is not None:
            await self.network.broadcast(self.id, Message('SEND', self.id, value_to_send))

        try:
            while True:
                msg = await asyncio.wait_for(self.inbox.get(), timeout=timeout)
                await self._handle(msg)
                if self.delivered is not None:
                    break
        except asyncio.TimeoutError:
            pass

    async def _handle(self, msg: Message):
        v = msg.value
        if msg.typ == 'SEND':
            if v not in self.sent_echo and self.honest:
                self.sent_echo.add(v)
                await self.network.broadcast(self.id, Message('ECHO', self.id, v))
        elif msg.typ == 'ECHO':
            self.echo_senders[v].add(msg.sender)
            if len(self.echo_senders[v]) >= self.echo_thresh and v not in self.sent_ready and self.honest:
                self.sent_ready.add(v)
                await self.network.broadcast(self.id, Message('READY', self.id, v))
        elif msg.typ == 'READY':
            self.ready_senders[v].add(msg.sender)
            if len(self.ready_senders[v]) >= self.ready_threshold and v not in self.sent_ready and self.honest:
                self.sent_ready.add(v)
                await self.network.broadcast(self.id, Message('READY', self.id, v))
            if len(self.ready_senders[v]) >= self.deliver_threshold and self.delivered is None and self.honest:
                self.delivered = v
                self.deliver_time = time.perf_counter() - self.start_time


async def simulate(n=7, faulty=None, sender_id=0, value="VALUE", delay_range=(0.005, 0.02), timeout=5.0, f=None):
    if faulty is None:
        faulty = set()
    if f is None:
        f = len(faulty) if faulty else (n - 1) // 3
    if n < 3 * f + 1:
        raise ValueError(f"n must be >= 3f+1, got n={n}, f={f}")

    net = Network(delay_range=delay_range)
    nodes = []
    for i in range(n):
        is_sender = (i == sender_id)
        honest = (i not in faulty)
        node = Node(i, n, f, net, is_sender=is_sender, honest=honest)
        net.register(node)
        nodes.append(node)

    tasks = []
    for node in nodes:
        val = value if node.is_sender else None
        tasks.append(asyncio.create_task(node.run(value_to_send=val, timeout=timeout)))

    start = time.perf_counter()
    deadline = start + timeout
    while time.perf_counter() < deadline:
        if all((node.delivered is not None) or (not node.honest) for node in nodes):
            break
        await asyncio.sleep(0.01)

    for t in tasks:
        if not t.done():
            t.cancel()
    try:
        await asyncio.gather(*tasks, return_exceptions=True)
    except Exception:
        pass

    return [
        {"id": node.id, "honest": node.honest, "delivered": node.delivered, "deliver_time": node.deliver_time}
        for node in nodes
    ]


def pretty_print_results(results):
    delivered = [r for r in results if r["delivered"] is not None and r["honest"]]
    not_delivered = [r for r in results if r["delivered"] is None and r["honest"]]
    honest_count = len([r for r in results if r["honest"]])
    print(f"Honest nodes delivered: {len(delivered)}/{honest_count}")
    if delivered:
        times = [r["deliver_time"] for r in delivered]
        print(f" min: {min(times):.4f}s  max: {max(times):.4f}s  avg: {sum(times)/len(times):.4f}s")
    if not_delivered:
        print("Honest nodes not delivered:", [r["id"] for r in not_delivered])
    print("\nPer-node:")
    for r in results:
        print(f" node {r['id']:>3}  honest={r['honest']}  delivered={r['delivered']}  time={r['deliver_time']}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Bracha Reliable Broadcast (RBC)")
    parser.add_argument("--n", type=int, default=7, help="number of nodes")
    parser.add_argument("--sender", type=int, default=0, help="sender node id")
    parser.add_argument("--faulty", type=str, default="", help="comma-separated faulty node ids, e.g. 1,2,3")
    parser.add_argument("--timeout", type=float, default=5.0, help="timeout in seconds")
    args = parser.parse_args()

    faulty_set = set()
    if args.faulty:
        faulty_set = {int(x.strip()) for x in args.faulty.split(",") if x.strip()}

    random.seed(42)
    start_all = time.perf_counter()
    res = asyncio.run(simulate(
        n=args.n,
        faulty=faulty_set,
        sender_id=args.sender,
        value="HELLO",
        delay_range=(0.001, 0.01),
        timeout=args.timeout,
    ))
    total_time = time.perf_counter() - start_all

    print(f"\nRBC Simulation n={args.n}, faulty={faulty_set}, wall time {total_time:.4f}s")
    pretty_print_results(res)
