# Limitations and Threat to Validity

## 1. Experimental and Technical Limitations

While TenantCache provides a rigorous, scientifically validated framework for verifying cache isolation in multi-tenant web applications, several technical and scope boundaries must be acknowledged.

---

### 1.1 Synthetic Canaries vs. Unstructured In-Wild Payloads
- **Current Approach:** TenantCache injects cryptographically verifiable canaries (`TC_CANARY_<uuid>_<hash>`) into synthetic resource fields. This guarantees zero false positives and mathematically indisputable taint tracking.
- **Limitation:** In legacy or black-box third-party enterprise applications where synthetic canaries cannot be injected into backend databases, detection must rely on heuristic diffing or schema-informed property extraction, which re-introduces potential false positives.

### 1.2 Multi-Tier Intermediate Cache Topologies
- **Current Approach:** The framework validates single-tier and dual-tier reverse-proxy caching (e.g. Nginx proxy cache or CDN edge cache).
- **Limitation:** In complex enterprise architectures with multi-tiered hierarchical caching (Browser Cache $\to$ Corporate Forward Proxy $\to$ CDN Edge $\to$ Cloud Shield $\to$ Origin Reverse Proxy), cache keys and normalization rules may diverge across multiple tiers simultaneously, requiring multi-point diagnostic instrumentation.

### 1.3 Asynchronous Eventual Consistency in Distributed Invalidation
- **Current Approach:** Evaluates instantaneous revocation versus proxy TTL expiration.
- **Limitation:** In globally distributed CDN networks (e.g. Akamai, Cloudflare), cache purge commands take a non-zero propagation time (typically 150ms to 5 seconds). TenantCache evaluates synchronous local state; in distributed CDN deployments, a grace window must be accounted for before classifying delayed purges as security failures.

### 1.4 Cache Concurrency and Race Conditions
- **Current Approach:** Focuses on deterministic sequential transitions ($P_A \to P_B$).
- **Limitation:** Concurrent race conditions (e.g., Cache Stampede / Thundering Herd where two users query an uncached endpoint simultaneously and proxy coalesces backend requests) require high-concurrency stress testing harnesses.

---

## 2. Threats to Scientific Validity

### 2.1 Internal Validity
- **Potential Bias:** Synthetic test applications might be structured to fit the testing model.
- **Mitigation:** We implemented RFC 9111 normative standards, real FastAPI backends, authentic Nginx configuration archetypes, and tested both vulnerable and secure configurations using identical test matrices.

### 2.2 External Validity
- **Generalizability:** The framework was tested on Nginx and HTTP RFC 9111 compliant proxies. Other cache systems (e.g., Varnish, Apache Traffic Server, Envoy, Squid) may employ distinct internal cache-key hashing schemes, although the HTTP semantics remain protocol-standard.
