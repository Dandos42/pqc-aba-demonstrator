# PQC Attribute-Based Authentication Demonstrator

![C](https://img.shields.io/badge/c-%2300599C.svg?style=for-the-badge&logo=c&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)
![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)
![JavaScript](https://img.shields.io/badge/javascript-%23323330.svg?style=for-the-badge&logo=javascript&logoColor=%23F7DF1E)

## About the Project
This application serves as a demonstrator of an attribute-based authentication (ABA) ecosystem utilizing lattice-based post-quantum cryptography and Zero-Knowledge Proofs (ZKP).
The cryptographic core is based on the *Signature with Efficient Protocols (SEP)* scheme proposed in the paper:

Research Paper: [Practical Post-Quantum Signatures for Privacy](https://eprint.iacr.org/2024/131.pdf)
Original Authors: Sven Argo, Tim Güneysu, Corentin Jeudy, Georg Land, Adeline Roux-Langlois, Olivier Sanders
Original Implementation: [GitHub Repository of the authors](https://github.com/Chair-for-Security-Engineering/lattice-anonymous-credentials)


### Original Authors’ Contribution
The original implementation provides:
  Low-level lattice cryptography implementation
  Zero-Knowledge Proof schemes
  Cryptographic primitives
  Mathematical lattice operations
  Benchmarking utilities

## Quick Start (Build & Run)

### Sestavení Docker obrazu
docker build -t lac_api .

### Spuštění kontejneru
docker run -d -p 8000:8000 --name lac_demo lac_api
