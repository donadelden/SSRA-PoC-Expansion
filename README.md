# SSRA-PoC Journal Extension

This repository extends the original SSRA workshop PoC with a minimal journal artifact.
The original commands are preserved, the RABE dependency is included in `ssra/rabe/`.

## Build with Docker

While this could be theoretically be complied natively, the best solution is to run it using Docker:

```bash
cd ssra
docker build -t ssra .
```

## Journal-extension commands

All journal commands write CSV files under `shared/results/`.  
Commands related to the data path, refresh, replay, and certificate validation also emit metadata-only audit records under `ssra/shared/audit/audit.csv`.

```bash
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra bench-crypto 1000 10 1
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra bench-policy 5 1
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra e2e 4096 1 1 10 1
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra rotate 100 1048576
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra bench-keyissue 4
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra bench-bundle
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra bench-audit 1000000
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra attack-replay
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra attack-mtls
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra attack-policy
```

## Audit output

The audit log is:

```
shared/audit/audit.csv
```

with fields:

```
timestamp_ms,event_type,actor,pseudonym,policy_id,seq,decision,reason
```

The log is metadata-only: it does not contain plaintext patient data.  
The prototype intentionally does not implement a trusted or tamper-evident logger. 
It records or submits metadata-only operational events; deployment-grade tamper evidence requires protected storage, signatures, external checkpoints, or replication.

The `bench-audit` command measures the cost of the *optional* tamper-evident variant: each metadata-only record is folded into a SHA-256 hash chain
(`h_i = SHA256(h_{i-1} || record_i)`), exactly as an external checkpointing component would.  
It writes `shared/results/bench_audit.csv` comparing the per-event cost of metadata-only logging versus the chained variant.  
Chaining does **not** make the Server trusted (a compromised logger can still truncate or rewrite its own chain); it provides tamper-evidence only with respect to an external party retaining the last hash.  The measured chain overhead is on the order of one microsecond per event, independent of payload size and policy complexity.

## Scope and caveats

- CP-ABE operations are real RABE/BSW calls.
  - The payload layer used by `e2e` and `rotate` is real AES-256-GCM authenticated encryption (nonce || ciphertext || tag), matching the paper's specification for the symmetric payload layer.
- `rotate` measures wrapper-level re-wrapping as a systems mechanism; it does not claim formal CP-ABE proxy re-encryption security.
- `attack-mtls` is a logical certificate-validation harness, not a live TLS session.
- SR7 support is local metadata-only audit-event generation and counting, not a trusted or tamper-evident audit infrastructure.


Notes:
- `bench-keyissue` sweeps user-key re-issuance scaling (10^1 .. 10^max_exp).
- `bench-bundle` reports stored bundle component sizes (payload ct, wrapper, metadata, audit record) for representative payload sizes.

## Utils

The `utils` directory contains convenience scripts and helpers used to run
experiments and summarise results:

- `utils/run_exp.sh`: Collection of `docker run` invocations that reproduce the paper tables (e2e, bench-crypto, bench-policy, rotate, etc.) and moves the generated CSVs into named files under `shared/results/`.
- `utils/run_exp_rpi.sh`: A variant of `run_exp.sh` that tags output CSVs with a `-rpi` suffix (contains only the script to be run in a Raspberry Pi).
- `utils/stats.py`: Small Python utility that computes mean and standard deviation for numeric CSV columns and prints a compact (LaTeX-friendly)   summary line for inclusion in tables.


## Original paper commands

```bash
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra tutor
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra robot 1000
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra user
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra all 1000
```