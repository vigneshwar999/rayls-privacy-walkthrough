# rayls-privacy-walkthrough

Follows one bank-to-bank payment through Rayls' private-network cryptography, using the functions from Rayls' open-source code:

- message encryption and tagging between two banks (relayer)
- a bank sharing its View key with the network auditor (relayer)
- the auditor recovering keys and decrypting for compliance (governance service)
- key rotation

Functions are copied from these pinned commits, with the Go standard-library versions of their imports (crypto/mlkem, crypto/sha3, crypto/hkdf, AES-GCM). No logic is changed.

- raylsnetwork/rayls-sovereign-relayer @ b01b427de4cfc2ac66e75eba0d5070b73a3b137c
- raylsnetwork/rayls-sovereign-pnh-governance @ 2f2bf83ab08805e42c7d4f0f60cbb232572c6ac3

## Run

Requires Go 1.24 or newer.

    go run .

It prints each step and writes `walkthrough.json`. Keys are generated fresh on every run, so hex values differ between runs; the true/false results do not.

## Scope

Runs locally. It does not connect to any network and uses no real data. Privacy Nodes (full chains) and Enygma's zero-knowledge batching are not run.

Written for "What can an outsider verify about Rayls?", Part 3.
