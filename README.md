# BitcoinVero

**Verifiable Bitcoin on-chain data and UTXO analytics.**

BitcoinVero is an independent research project focused on reproducible
Bitcoin data processing, UTXO state reconstruction, provenance,
integrity verification, deterministic auditing, and on-chain analytics.

> **Bitcoin data should be independently verifiable, not merely displayed.**

## Scope

BitcoinVero includes components for:

- Bitcoin UTXO state reconstruction
- historical blockchain processing
- deterministic APPLY pipelines
- provenance and lineage verification
- independent audit workflows
- UTXO and on-chain metric calculation
- canonical stage construction
- operator tooling
- analytical indicators
- backtesting and visualization

## Core components

### Current execution and verification

- `utxo_pipeline_v50_r13.py` — current experimental R13 UTXO/APPLY execution layer
- `utxo_pipeline_audit_v51_5_5.py` — independent audit and verification engine
- `utxo_metrics_v4` — UTXO and on-chain metric calculation layer

### Stage and operator layer

- `utxo_core_v2/build_stage.py` — canonical stage construction
- `utxo_core_v2/operator/` — operator and orchestration tooling
- `build_canonical_transactions.py` — canonical transaction extraction
- `stage2_decoder_preflight.py` — Stage2 decoding/preflight
- `build_block_locator.py` — block locator generation

### Historical / provenance-pinned components

Selected earlier pipeline generations are retained because reproducibility
and provenance verification may depend on the exact implementation that
originally produced a state.

Included historical components include:

- `utxo_pipeline_v30.py`
- `utxo_pipeline_v40.py`
- `utxo_pipeline_v41.py`
- `utxo_pipeline_v50.py`
- `utxo_pipeline_v50_r12_9.py`

Their presence does not mean they are the current recommended execution
entry points.

### Analytics layer

- `app.py` — analytics application
- `backtest_runner.py` — backtesting engine
- `aws_indicator_pipeline.py` — indicator processing
- `indicators/` — indicator framework
- `plots.py` — visualization
- `data_io.py` — analytical data I/O

## Reproducibility model

BitcoinVero treats the following as distinct layers:

1. source blockchain data
2. canonical derived stage data
3. mutable execution state
4. calculation logic
5. provenance evidence
6. independent audit evidence

A newer implementation does not automatically replace an older implementation
for verification of historical state.

Exact source identity and cryptographic hashes may form part of execution
and verification contracts.

## Optional diagnostics

R13 may contain an explicitly opt-in diagnostics layer.

Diagnostics are disabled by default and are logically separated from
authoritative UTXO state-transition semantics and mandatory safety guards.

Diagnostic functionality must not be interpreted as part of the
money-critical calculation contract unless explicitly stated otherwise.

## Runtime environment

This repository contains source code but does not contain:

- Bitcoin blockchain datasets
- production UTXO databases
- credentials or private keys
- production state
- runtime logs
- environment-specific secrets

A complete execution environment requires external Bitcoin blockchain data,
local storage, and appropriate compute resources.

Reference deployment paths such as:

- `/root/mybot`
- `/opt/mybot_data`
- `/opt/mybot_tmp`
- `/var/lib/tikctl`

may appear in source code. They reflect the reference deployment environment
and are not credentials.

## Development status

BitcoinVero is actively developed research software.

Interfaces, internal contracts, storage formats, operational procedures,
and processing semantics may change.

Components explicitly marked experimental must not be interpreted as
production-certified releases.

Do not rely on this repository for financial decisions or production
operation without independently reviewing the implementation, provenance,
resource requirements, and applicable verification procedures.

## License

**Educational and non-commercial research use only.**

BitcoinVero is source-available software and is **not** distributed under
an OSI-approved open-source license.

Commercial use, production use, SaaS/API hosting, redistribution,
publication of derivative versions, AI/ML training, and other uses prohibited
by the license require prior written permission.

See [LICENSE](LICENSE).

## Disclaimer

BitcoinVero is an independent project and is not affiliated with Bitcoin Core,
its maintainers, or any unrelated project using the name Bitcoin Vero.

Third-party software, names, marks, and projects referenced by BitcoinVero
remain subject to their respective licenses and rights.

BitcoinVero does not provide investment, trading, legal, tax, or financial
advice.

The software is provided without warranty.

## Website

https://bitcoinvero.com

---

Copyright © 2026 Kirill Kiselev. All rights reserved.
