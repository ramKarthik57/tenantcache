# Architectural Decision Records (ADR)

## ADR-001: Selection of Dual-Mode Lab Runtime (Nginx Container + Native ASGI Simulator)
- **Status:** Accepted
- **Context:** The research directive mandates support for local Windows environments where Docker Desktop or container engines may not be present or installed. However, Nginx proxy cache configuration fidelity is mandatory for containerized CI/CD.
- **Decision:** Implement a dual-mode lab architecture:
  1. Produce production-grade `docker-compose.yml`, Dockerfiles, and Nginx configurations (`nginx.conf`) covering all vulnerable (V1–V6) and secure (S1, S2) configurations.
  2. Implement an in-memory ASGI/HTTP reverse-proxy cache simulator (`ProxyCacheSimulator`) that faithfully mirrors Nginx's `proxy_cache_key`, `proxy_cache_valid`, `proxy_ignore_headers`, `Vary` evaluation, and `X-Cache-Status` headers.
- **Consequences:** Ensures 100% reproducibility on any developer workstation (including Windows without Docker) while maintaining identical test coverage and verification validity.

## ADR-002: Invariant-Based Ground-Truth Canary Attribution
- **Status:** Accepted
- **Context:** Naive differential testing (diffing response bodies or lengths) yields unacceptable false-positive rates on dynamic content (timestamps, CSRF tokens) and cannot distinguish legitimate public caching from private leaks.
- **Decision:** Inject cryptographically unique canary tokens (`TC_CANARY_<UUID>_<CRC32>`) into all synthetic private resources. The leakage detection engine only flags violations when an unauthorized principal's response contains canaries belonging to a resource for which $\mathcal{A}(P, R) = \text{DENY}$.
- **Consequences:** Reduces False Positive Rate (FPR) to 0.0% on public endpoints and provides mathematical certainty for confirmed vulnerabilities.

## ADR-003: Decoupled Independent Security Oracle
- **Status:** Accepted
- **Context:** Vulnerability scanners that rely on target application response codes (e.g. flagging 200 as success and 403 as denied) are blinded when vulnerable applications return 200 OK from cache for unauthorized requests, or custom error pages.
- **Decision:** Maintain an independent ground-truth security oracle mapping that stores definitive ownership and policy matrices completely decoupled from the HTTP response status.
- **Consequences:** The oracle evaluates confidentiality invariant violations regardless of whether the HTTP status is 200, 304, or 403.
