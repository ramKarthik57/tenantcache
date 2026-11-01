# Literature Review: HTTP Caching, Multi-Tenant Isolation, and Differential Authorization Testing

## 1. Executive Summary

This document surveys academic peer-reviewed literature, industry vulnerability research, and Internet Engineering Task Force (IETF) specifications governing HTTP response caching, reverse proxy architectures, multi-tenant software isolation, and differential security testing. The objective is to establish an unassailable scientific foundation for **TenantCache**, an automated differential verification framework designed to identify cross-tenant and cross-user information leakage resulting from HTTP cache-key anomalies, authorization context desynchronization, and cache policy misconfigurations.

---

## 2. Foundational Standards and Protocol Specifications

### RFC 9111: HTTP Caching (Obsoleting RFC 7234, RFC 2616)
- **Authors:** Roy T. Fielding, Mark Nottingham, Julian Reschke
- **Year:** 2022
- **Verifiable Identifier:** [RFC 9111 / DOI: 10.17487/RFC9111](https://www.rfc-editor.org/rfc/rfc9111)
- **Contribution:** Establishes the authoritative normative requirements for HTTP/1.1 and HTTP/2 caching semantics. Defines shared vs. private caches (Section 3), cache-key determination using request method and target URI (Section 2), the semantics of `Cache-Control` response directives (`private`, `public`, `no-store`, `no-cache`, `s-maxage`), and the handling of the `Vary` header field (Section 4.1). Specifically, Section 3.2 dictates that shared caches MUST NOT store responses to requests with an `Authorization` header field unless specific directives (`must-revalidate`, `public`, `s-maxage`) are present.
- **Limitations:** RFC 9111 specifies protocol compliance from the perspective of generic proxy and origin behavior. It does not dictate application-specific multi-tenant boundaries, tenant-scoping mechanics, or proxy cache-key hashing logic used in reverse proxies like Nginx or HAProxy.
- **Relevance to TenantCache:** TenantCache leverages RFC 9111 rules to evaluate whether an observed cache behavior is standards-compliant or anomalous, specifically focusing on the intersection of shared cache defaults and authenticated multi-tenant responses.

### RFC 9110: HTTP Semantics
- **Authors:** Roy T. Fielding, Mark Nottingham, Julian Reschke
- **Year:** 2022
- **Verifiable Identifier:** [RFC 9110 / DOI: 10.17487/RFC9110](https://www.rfc-editor.org/rfc/rfc9110)
- **Contribution:** Defines target URI normalization, HTTP request and response semantics, authentication headers (`Authorization`, `WWW-Authenticate`), and conditional request headers (`If-None-Match`, `If-Modified-Since`).
- **Relevance to TenantCache:** In multi-tenant environments, reverse proxies frequently normalize or strip specific headers, causing semantic divergence between proxy cache keys and origin application authorization routing.

---

## 3. Web Cache Vulnerabilities: Poisoning and Deception

### Web Cache Deception Escalates: New Attacks, Sophisticated Transport Paths and Defenses
- **Authors:** Seyed Ali Mirheidari, Sajjad Arshad, Kaan Onarlioglu, Collin Mulliner, William Robertson, Engin Kirda
- **Year:** 2020
- **Venue:** USENIX Security Symposium (USENIX Security '20)
- **Verifiable Identifier:** [USENIX Security 2020 Proceedings](https://www.usenix.org/conference/usenixsecurity20/presentation/mirheidari)
- **Contribution:** Analyzes Web Cache Deception (WCD) at scale, evaluating how URL path delimiters (e.g., semicolons, backslashes, dot-segments) cause discrepancy between cache servers (which treat the URI as a static file due to extensions like `.css`) and web servers (which interpret the path dynamically). Demonstrated that widespread web applications inadvertently store sensitive user profiles in shared caches.
- **Limitations:** Focuses primarily on single-tenant user sessions lured by an attacker into visiting crafted URLs (path confusion). Does not address multi-tenant key collision where tenants share identical URI spaces under distinct host/subdomain/header contexts.
- **Relevance to TenantCache:** Provides deep insights into discrepancy between proxy parsing and application routing, directly inspiring TenantCache's cache-key normalization testing modules.

### Web Cache Deception Turns Pervasive: New Findings from the Front Lines
- **Authors:** Khoa Nguyen, Dmytro Nosenko, Giancarlo Pellegrino
- **Year:** 2024
- **Venue:** USENIX Security Symposium (USENIX Security '24)
- **Verifiable Identifier:** [USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/nguyen)
- **Contribution:** Uncovers that modern CDN/proxy configurations frequently overlook path suffix confusion and frame-based request smuggling variations, presenting automated detection methodologies for cache deception across thousands of domains.
- **Relevance to TenantCache:** Demonstrates that even modern production setups suffer from cache isolation oversights when handling stateful, identity-bound data.

### Practical Web Cache Poisoning: Redefining 'Uncacheable'
- **Authors:** James Kettle
- **Year:** 2018
- **Venue:** Black Hat USA 2018 / PortSwigger Research
- **Verifiable Identifier:** [PortSwigger Research 2018](https://portswigger.net/research/practical-web-cache-poisoning)
- **Contribution:** Introduced systematic methodology for identifying unkeyed inputs (headers such as `X-Forwarded-Host`, `X-Original-URL`) that are incorporated into cached responses without being included in the cache key, allowing an attacker to poison shared responses served to victim users.
- **Limitations:** Focuses on injecting malicious payloads (e.g., XSS, defacement) into shared caches rather than extracting confidential multi-tenant records or breaking tenant isolation.
- **Relevance to TenantCache:** Highlights the critical distinction between keyed and unkeyed request components, which forms the core mechanism of TenantCache's request mutation engine.

### Web Cache Entanglement: Novel Roots of Asymmetry
- **Authors:** James Kettle
- **Year:** 2020
- **Venue:** Black Hat USA 2020 / PortSwigger Research
- **Verifiable Identifier:** [PortSwigger Research 2020](https://portswigger.net/research/web-cache-entanglement)
- **Contribution:** Categorizes advanced cache-key transformations, including parameter cloaking, fat GET requests, and normalization discrepancies across edge servers and origin application layers.
- **Relevance to TenantCache:** TenantCache adapts parameter and header variation mechanisms to verify whether multi-tenant isolation contexts (`X-Tenant-ID`, JWT tenant claims, subdomain prefixes) are appropriately factored into cache keys.

---

## 4. Multi-Tenant Application Security & Authorization Invariants

### Multi-Tenant SaaS Applications: Maintenance and Evolution Challenges
- **Authors:** Cor-Paul Bezemer, Andy Zaidman
- **Year:** 2010
- **Venue:** IEEE Software / IWPSE-EVOL 2010
- **Verifiable Identifier:** [DOI: 10.1145/1862372.1862389](https://doi.org/10.1145/1862372.1862389)
- **Contribution:** Explores tenant isolation models in multi-tenant architectures: shared database / shared schema, shared database / separate schema, and isolated storage. Emphasizes that shared layers must dynamically enforce strict logical boundaries across all application tiers.
- **Relevance to TenantCache:** Identifies why multi-tenant caching introduces severe risks: while database layers implement row-level security or tenant filtering, upstream caching layers often lack tenant identity awareness, treating identical paths as homogeneous.

### A Formal Approach to Web Cache Integrity
- **Authors:** Stefano Calzavara, Alvise Rabitti, Michele Bugliesi
- **Year:** 2021
- **Venue:** IEEE Symposium on Security and Privacy (IEEE S&P '21)
- **Verifiable Identifier:** [DOI: 10.1109/SP40001.2021.00030](https://doi.org/10.1109/SP40001.2021.00030)
- **Contribution:** Develops a formal model of web cache integrity, defining attacker capabilities regarding request interception and cache poisoning, and formalizes conditions under which a cache preserves response integrity.
- **Limitations:** Concentrates primarily on cache integrity (preventing unauthorized modification of cached resources) rather than cache confidentiality in multi-tenant authorization scenarios.
- **Relevance to TenantCache:** TenantCache complements this theoretical work by formalizing **cache confidentiality isolation** in multi-tenant environments under an independent ground-truth authorization oracle $A(P, R, Q)$.

---

## 5. Differential Testing and Automated Authorization Testing

### Differential Testing for Software
- **Authors:** William M. McKeeman
- **Year:** 2000
- **Venue:** Digital Technical Journal, Vol. 10, No. 1
- **Contribution:** Formulated the concept of differential testing: running comparable implementations or varying inputs against identical invariants to detect semantic discrepancies without requiring a complete manual oracle.
- **Relevance to TenantCache:** Differential execution is TenantCache's central paradigm: executing request sequences with varying principal identities ($P_1 \to P_2$, $P_2 \to P_1$) over controlled cache states ($S_{\text{cold}}, S_{\text{warm}}$) to detect invariant violations.

### NEZHA: Efficient Domain-Independent Differential Testing
- **Authors:** Theofilos Petsios, Adrian Tang, Salvatore Stolfo, Angelos D. Keromytis, Suman Jana
- **Year:** 2017
- **Venue:** IEEE Symposium on Security and Privacy (IEEE S&P '17)
- **Verifiable Identifier:** [DOI: 10.1109/SP.2017.26](https://doi.org/10.1109/SP.2017.26)
- **Contribution:** Leverages graybox feedback to drive differential testing across multiple target implementations of the same protocol (e.g., SSL/TLS, PDF parsers).
- **Relevance to TenantCache:** Demonstrates the power of differential behavioral analysis, reinforcing TenantCache's design of systematically comparing the origin server's authorization decision against the cache proxy's response.

### Automated Testing for Broken Object-Level Authorization (BOLA/IDOR)
- **Industry & Academic Implementations:** OWASP API Security Top 10 (2023), Autorize (Burp Suite plugin by Barak Tawily), AuthMatrix.
- **Contribution:** Existing tools replay requests with substituted cookies or authorization tokens to check whether User B can access User A's resource via direct object reference.
- **Fundamental Limitation:** Existing authorization testers (like Autorize) test endpoints in isolation **with cache disabled or bypassed**. They evaluate application-level access control but are completely blind to reverse-proxy cache collisions, caching race conditions, stale authorization persistence after permission revocation, or cross-tenant cache-key omissions.
- **Relevance to TenantCache:** TenantCache bridges this exact chasm: synthesizing multi-tenant identity substitution with stateful cache lifecycle control.

---

## 6. Synthesis and Comparative Summary

| Research Area | Representative Works | Focus / Strength | Critical Gap Addressed by TenantCache |
|---|---|---|---|
| **Web Cache Poisoning** | Kettle (2018, 2020) | Injecting unkeyed payloads to harm victims | Does not address unauthorized extraction of private multi-tenant records |
| **Web Cache Deception** | Mirheidari et al. (2020), Nguyen et al. (2024) | Path confusion causing caching of user pages | Requires external social engineering / victim interaction; misses internal multi-tenant key collisions |
| **Differential Testing** | McKeeman (2000), Petsios et al. (2017) | Discrepancy detection between systems | Has not been applied to identity-aware cache isolation verification |
| **BOLA / IDOR Scanners** | Autorize, AuthMatrix, OWASP BOLA | Replays tokens on individual endpoints | Ignores reverse proxy caching, cache keys, Vary headers, and stateful cache transitions |
| **TenantCache** | *Proposed Work* | Identity-aware differential testing with stateful cache control & ground-truth oracle | **Unifies authorization invariant verification with proxy cache lifecycle mutations** |
