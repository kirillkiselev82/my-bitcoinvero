# BitcoinVero

**Verifiable Bitcoin on-chain data and UTXO analytics.**

BitcoinVero is a research and analytics platform focused on reproducible Bitcoin data processing, UTXO state analysis, on-chain metrics, provenance, verification, and auditing.

## Project scope

BitcoinVero includes components for:

- Bitcoin UTXO state reconstruction
- on-chain metric calculation
- historical blockchain data processing
- provenance and integrity verification
- deterministic audit workflows
- stage/build pipelines
- operator tooling
- analytical indicators and visualization

## Core components

- `utxo_pipeline_v50_r13.py` — current UTXO/APPLY pipeline
- `utxo_pipeline_audit_v51_5_5.py` — audit and verification engine
- `utxo_metrics_v4` — metric calculation layer
- `utxo_core_v2/` — stage builder and operator components
- `indicators/` — on-chain indicator framework
- `app.py` — application layer

## Status

This repository contains actively developed research software.

Interfaces, storage formats, internal contracts, and data-processing semantics may change between versions.

Do not rely on this repository for financial decisions or production workloads.

## ⚠️ License Notice

**Educational and non-commercial research use only.**

BitcoinVero source code is provided for study, testing, and non-commercial research.

**Commercial use, production use, SaaS/API hosting, redistribution, publication of modified versions, and incorporation into commercial products are prohibited without prior written permission.**

This is **not an open-source license**.

See [LICENSE](LICENSE) for the complete terms.

## Disclaimer

BitcoinVero is independent software and is not affiliated with Bitcoin Core or any unrelated project using the name Bitcoin Vero.

Bitcoin and Bitcoin Core are trademarks or projects belonging to their respective owners and communities.

This software is provided without warranty.

## Website

https://bitcoinvero.com
