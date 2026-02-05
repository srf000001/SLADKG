# Broadcast Protocols - RBC & OPRBC

RBC (Bracha Reliable Broadcast) and OPRBC (Optimistic Reliable Broadcast) simulators.

## Files

- `RBC.py` - Bracha Reliable Broadcast implementation
- `OPRBC.py` - Optimistic Reliable Broadcast implementation
- `run_tests.py` - Unified test script

## Usage

### Run tests (both protocols)

```bash
cd broadcast
python run_tests.py --n 7
```

### Run with options

```bash
# Test only RBC
python run_tests.py --protocol rbc --n 7

# Test only OPRBC
python run_tests.py --protocol oprbc --n 7

# With faulty nodes
python run_tests.py --n 10 --faulty 1,2,3

# Custom parameters
python run_tests.py --n 31 --sender 0 --timeout 10 --value "TEST"
```

### Direct invocation

```bash
# RBC
python RBC.py --n 7 --sender 0 --faulty ""

# OPRBC
python OPRBC.py --n 7 --sender 0 --faulty ""
```

## Parameters

| Argument   | Description                    | Default |
|-----------|--------------------------------|---------|
| --n       | Number of nodes                | 7       |
| --sender  | Sender node id                 | 0       |
| --faulty  | Comma-separated faulty node ids| ""      |
| --timeout | Simulation timeout (seconds)   | 5.0     |
| --protocol| rbc, oprbc, or both            | both    |

## Protocol Requirements

- Both protocols require **n ≥ 3f + 1**, where f is the maximum number of faulty nodes.
- Faulty nodes are modeled as silent (they do not send messages).
