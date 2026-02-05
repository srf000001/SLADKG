"""
Optimistic Reliable Broadcast (OPRBC)
(2,3,4) Optimistic reliable broadcast under n ≥ 3f + 1
"""

import asyncio
import random
import time
import math
from collections import defaultdict


class Message:
    def __init__(self, typ, sender, value):
        self.typ = typ  # 'PROPOSE' | 'ECHO' | 'VOTE' | 'READY'
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
    def __init__(self, node_id, n, f, network, sender_id=0, honest=True):
        self.id = node_id
        self.n = n
        self.f = f
        self.network = network
        self.is_sender = (node_id == sender_id)
        self.sender_id = sender_id
        self.honest = honest

        self.inbox = asyncio.Queue()
        self.echo_senders = defaultdict(set)
        self.vote_senders = defaultdict(set)
        self.ready_senders = defaultdict(set)
        self.sent_echo = set()
        self.sent_vote = set()
        self.sent_ready = set()
        self.received_propose = set()
        self.delivered = None
        self.start_time = None
        self.deliver_time = None
        self.commit_path = None

        self.non_broadcaster = n - 1
        self.vote_threshold = math.ceil(n / 2)
        self.ready_echo_threshold = math.ceil((n + f - 1) / 2)
        self.ready_vote_threshold = math.ceil((n + f - 1) / 2)
        self.ready_ready_threshold = f + 1
        self.opt_commit_threshold = math.ceil((n + 2 * f - 2) / 2)
        self.normal_commit_threshold = 2 * f + 1

    def _is_non_broadcaster(self, sender_id):
        return sender_id != self.sender_id

    async def run(self, value_to_send=None, timeout=5.0):
        self.start_time = time.perf_counter()
        if self.is_sender and self.honest and value_to_send is not None:
            await self.network.broadcast(self.id, Message('PROPOSE', self.id, value_to_send))

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

        if msg.typ == 'PROPOSE':
            if v not in self.received_propose and self.honest:
                self.received_propose.add(v)
                if v not in self.sent_echo:
                    self.sent_echo.add(v)
                    await self.network.broadcast(self.id, Message('ECHO', self.id, v))

        elif msg.typ == 'ECHO':
            if self._is_non_broadcaster(msg.sender):
                self.echo_senders[v].add(msg.sender)
                echo_count = len(self.echo_senders[v])

                if echo_count >= self.vote_threshold and v not in self.sent_vote and self.honest:
                    self.sent_vote.add(v)
                    await self.network.broadcast(self.id, Message('VOTE', self.id, v))

                if echo_count >= self.ready_echo_threshold and v not in self.sent_ready and self.honest:
                    self.sent_ready.add(v)
                    await self.network.broadcast(self.id, Message('READY', self.id, v))

                if echo_count >= self.opt_commit_threshold and self.delivered is None and self.honest:
                    self.delivered = v
                    self.deliver_time = time.perf_counter() - self.start_time
                    self.commit_path = 'OPT'

        elif msg.typ == 'VOTE':
            if self._is_non_broadcaster(msg.sender):
                self.vote_senders[v].add(msg.sender)
                vote_count = len(self.vote_senders[v])
                if vote_count >= self.ready_vote_threshold and v not in self.sent_ready and self.honest:
                    self.sent_ready.add(v)
                    await self.network.broadcast(self.id, Message('READY', self.id, v))

        elif msg.typ == 'READY':
            self.ready_senders[v].add(msg.sender)
            ready_count = len(self.ready_senders[v])

            if ready_count >= self.ready_ready_threshold and v not in self.sent_ready and self.honest:
                self.sent_ready.add(v)
                await self.network.broadcast(self.id, Message('READY', self.id, v))

            if ready_count >= self.normal_commit_threshold and self.delivered is None and self.honest:
                self.delivered = v
                self.deliver_time = time.perf_counter() - self.start_time
                if self.commit_path is None:
                    self.commit_path = 'NORMAL'


async def simulate(n=7, f=None, faulty=None, sender_id=0, value="VALUE", delay_range=(0.005, 0.02), timeout=5.0):
    if f is None:
        f = len(faulty) if faulty else (n - 1) // 3
    if faulty is None:
        faulty = set()
    if n < 3 * f + 1:
        raise ValueError(f"n must be >= 3f+1, got n={n}, f={f}")

    net = Network(delay_range=delay_range)
    nodes = []
    for i in range(n):
        honest = (i not in faulty)
        node = Node(i, n, f, net, sender_id=sender_id, honest=honest)
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
        {
            "id": node.id,
            "honest": node.honest,
            "delivered": node.delivered,
            "deliver_time": node.deliver_time,
            "commit_path": node.commit_path,
        }
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
        opt = len([r for r in delivered if r.get("commit_path") == "OPT"])
        norm = len([r for r in delivered if r.get("commit_path") == "NORMAL"])
        if opt:
            print(f" Opt Commit: {opt} nodes")
        if norm:
            print(f" Normal Commit: {norm} nodes")
    if not_delivered:
        print("Honest nodes not delivered:", [r["id"] for r in not_delivered])
    print("\nPer-node:")
    for r in results:
        print(f" node {r['id']:>3}  honest={r['honest']}  delivered={r['delivered']}  path={r.get('commit_path')}  time={r['deliver_time']}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Optimistic Reliable Broadcast (OPRBC)")
    parser.add_argument("--n", type=int, default=7, help="number of nodes")
    parser.add_argument("--sender", type=int, default=0, help="sender node id")
    parser.add_argument("--faulty", type=str, default="", help="comma-separated faulty node ids")
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

    print(f"\nOPRBC Simulation n={args.n}, faulty={faulty_set}, wall time {total_time:.4f}s")
    pretty_print_results(res)
