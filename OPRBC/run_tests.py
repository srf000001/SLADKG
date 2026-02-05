#!/usr/bin/env python3
"""
Unified test script for RBC and OPRBC protocols.
Run both protocols with configurable parameters.
"""

import asyncio
import argparse
import time
import random

from RBC import simulate as simulate_rbc, pretty_print_results as print_rbc
from OPRBC import simulate as simulate_oprbc, pretty_print_results as print_oprbc


async def run_rbc(n, faulty, sender, timeout, delay_range, value):
    print("\n" + "=" * 60)
    print("RBC (Bracha Reliable Broadcast)")
    print("=" * 60)
    start = time.perf_counter()
    res = await simulate_rbc(
        n=n,
        faulty=faulty,
        sender_id=sender,
        value=value,
        delay_range=delay_range,
        timeout=timeout,
    )
    elapsed = time.perf_counter() - start
    print(f"n={n}, faulty={faulty}, wall time {elapsed:.4f}s")
    print_rbc(res)
    return res


async def run_oprbc(n, faulty, sender, timeout, delay_range, value):
    print("\n" + "=" * 60)
    print("OPRBC (Optimistic Reliable Broadcast)")
    print("=" * 60)
    start = time.perf_counter()
    res = await simulate_oprbc(
        n=n,
        faulty=faulty,
        sender_id=sender,
        value=value,
        delay_range=delay_range,
        timeout=timeout,
    )
    elapsed = time.perf_counter() - start
    print(f"n={n}, faulty={faulty}, wall time {elapsed:.4f}s")
    print_oprbc(res)
    return res


def parse_faulty(s: str):
    if not s or not s.strip():
        return set()
    return {int(x.strip()) for x in s.split(",") if x.strip()}


def main():
    parser = argparse.ArgumentParser(description="Test RBC and OPRBC protocols")
    parser.add_argument("--n", type=int, default=7, help="number of nodes")
    parser.add_argument("--sender", type=int, default=0, help="sender node id")
    parser.add_argument("--faulty", type=str, default="", help="comma-separated faulty node ids, e.g. 1,2,3")
    parser.add_argument("--timeout", type=float, default=5.0, help="timeout in seconds")
    parser.add_argument("--delay", type=float, nargs=2, default=[0.001, 0.01], metavar=("MIN", "MAX"),
                        help="delay range in seconds (default: 0.001 0.01)")
    parser.add_argument("--value", type=str, default="HELLO", help="value to broadcast")
    parser.add_argument("--protocol", choices=["rbc", "oprbc", "both"], default="both",
                        help="which protocol to run: rbc, oprbc, or both")
    parser.add_argument("--seed", type=int, default=42, help="random seed")
    args = parser.parse_args()

    faulty_set = parse_faulty(args.faulty)
    delay_range = tuple(args.delay)
    random.seed(args.seed)

    async def run_all():
        if args.protocol == "rbc":
            await run_rbc(args.n, faulty_set, args.sender, args.timeout, delay_range, args.value)
        elif args.protocol == "oprbc":
            await run_oprbc(args.n, faulty_set, args.sender, args.timeout, delay_range, args.value)
        else:
            await run_rbc(args.n, faulty_set, args.sender, args.timeout, delay_range, args.value)
            await run_oprbc(args.n, faulty_set, args.sender, args.timeout, delay_range, args.value)

    asyncio.run(run_all())


if __name__ == "__main__":
    main()
