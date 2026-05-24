# PQC & ZKP Attribute-Based Authentication Demonstrator

![C](https://img.shields.io/badge/c-%2300599C.svg?style=for-the-badge&logo=c&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)
![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)
![JavaScript](https://img.shields.io/badge/javascript-%23323330.svg?style=for-the-badge&logo=javascript&logoColor=%23F7DF1E)

## About the Project
This application serves as a demonstrator of an attribute-based authentication and self-sovereign identity (SSI) ecosystem. It utilizes **Post-Quantum Cryptography (PQC)** and **Zero-Knowledge Proofs (ZKP)** to achieve privacy-preserving identity verification.

The cryptographic core is based on the *Signature with Efficient Protocols (SEP)* scheme proposed in the paper:
> **"Practical Post-Quantum Signatures for Privacy"** (Argo et al., CCS '24).

This repository bridges the gap between low-level academic cryptography and practical software engineering by wrapping complex Module Learning With Errors (M-LWE) lattice operations into a modern, containerized Web API ecosystem.

---

## Quick Start (Build & Run)

### Sestavení Docker obrazu
docker build -t lac_api .

### Spuštění kontejneru
docker run -d -p 8000:8000 --name lac_demo lac_api
