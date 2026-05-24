# PQC Attribute-Based Authentication Demonstrator

![C](https://img.shields.io/badge/c-%2300599C.svg?style=for-the-badge&logo=c&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)
![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)
![JavaScript](https://img.shields.io/badge/javascript-%23323330.svg?style=for-the-badge&logo=javascript&logoColor=%23F7DF1E)

## About the Project
This application serves as a demonstrator of an attribute-based authentication (ABA) ecosystem utilizing lattice-based post-quantum cryptography and Zero-Knowledge Proofs (ZKP).
The cryptographic core is based on the *Signature with Efficient Protocols (SEP)* scheme proposed in the paper:

*   **Research Paper:** [Practical Post-Quantum Signatures for Privacy](https://eprint.iacr.org/2024/131.pdf)
*   **Original Authors:** Sven Argo, Tim Güneysu, Corentin Jeudy, Georg Land, Adeline Roux-Langlois, Olivier Sanders
*   **Original Implementation:** [GitHub Repository of the authors](https://github.com/Chair-for-Security-Engineering/lattice-anonymous-credentials)

### Original Authors’ Contribution
The original implementation provides:
*   Low-level lattice cryptography implementation
*   Zero-Knowledge Proof schemes
*   Cryptographic primitives
*   Mathematical lattice operations
*   Benchmarking utilities

### My Contribution
*   Refactoring the original monolithic cryptographic implementation into isolated C-kernel binaries for credential issuance, proof generation, and proof verification
*   Designing a modular backend orchestration layer using the FastAPI framework
*   Implementing secure credential and attribute storage using AES-256-GCM encryption
*   Developing issuer, wallet, prover, and verifier backend services
*   Implementing secure serialization/deserialization workflows between cryptographic modules
*   Integrating Zero-Knowledge Proof generation and verification workflows
*   Implementing replay attack mitigation through ephemeral proof handling
*   Developing automated test environment provisioning with predefined users and credentials
*   Creating a lightweight Single Page Application frontend using Vanilla JavaScript, HTML5, and CSS3
*   Implementing asynchronous frontend-backend communication using the Fetch API
*   Designing a demonstrator workflow simulating Issuer, Holder, and Verifier interactions within an SSI ecosystem
*   Implementing telemetry visualization and user interaction interfaces for cryptographic demonstrations

### Documentation & Benchmarks
Additional resources can be found in the `docs` directory:
* **Master's Thesis (`docs/TextPrace.pdf`):** Comprehensive documentation of the project, including theoretical background, architecture, and implementation details.
* **Benchmarks (`docs/benchmark.xlsx`):** Detailed performance measurements and metrics of the implemented cryptographic operations.
---

## Quick Start (Build & Run)
**Requirements:** 
*   Docker
*   Modern web browser

### Build Docker Image
```bash
docker build -t lac_api .
```
### Run Docker Container
```bash
docker run -d -p 8000:8000 --name lac_demo lac_api
```

### Using the Demonstrator
After successfully building and running the Docker container:

1. Open the `index.html` file in your web browser.
2. The demonstrator will automatically communicate with the backend API.
3. Detailed usage instructions are available directly in the application under the **User Manual** tab.
---

## Contributing
Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are greatly appreciated.
1. Fork the Project
2. Create your Feature Branch
```bash
git checkout -b feature/Name
```
3. Commit your changes
```bash
git commit -m "Add some"
```
4. Push to GitHub
```bash
git push origin feature/Name
```
5. Open a Pull Request

## Licence
Distributed under the GNU General Public License v3.0 (GPL-3.0). See the `LICENSE` file for more information.

## Contact
* Your Name: Bc. Daniel Prachař
* Email: 240969@vutbr.cz
* Project Link: [Project Link](https://github.com/Dandos42/pqc-aba-demonstrator)
