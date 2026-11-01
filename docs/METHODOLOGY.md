# Research Methodology: Differential Verification and Invariant Tracking

## 1. Mathematical Formulation of the Security Invariant

Let the system under test consist of:
- A set of principals $\mathcal{P} = \{P_1, P_2, \dots, P_n\}$, where each principal $P = (T_P, U_P, R_P)$ is defined by their tenant affiliation $T_P$, user identity $U_P$, and assigned role $R_P \in \{\text{Admin}, \text{StandardUser}, \text{Guest}\}$.
- A set of resources $\mathcal{R} = \{R_1, R_2, \dots, R_m\}$, where each resource $R = (T_R, \text{Owner}_R, \text{Visibility}_R, \mathcal{C}_R)$ is defined by tenant ownership $T_R$, individual owner $\text{Owner}_R$, visibility scope $\text{Visibility}_R \in \{\text{Public}, \text{TenantShared}, \text{UserPrivate}\}$, and a set of cryptographically unique canary tokens $\mathcal{C}_R$.
- A ground-truth authorization function $\mathcal{A}: \mathcal{P} \times \mathcal{R} \times \mathcal{Q} \to \{\text{ALLOW}, \text{DENY}\}$, where $\mathcal{Q}$ is the incoming HTTP request.
- An intermediate caching proxy $\mathcal{M}$ maintaining state $S \in \mathcal{S}_{\text{cache}}$.
- An observed HTTP response function $\text{Resp}(P, Q_R, S)$, returning an HTTP status code, headers, and response body $\mathcal{B}$.

### 1.1 The Confidentiality Invariant

$$\forall P \in \mathcal{P}, \forall R \in \mathcal{R}, \forall S \in \mathcal{S}_{\text{cache}}: \quad \mathcal{A}(P, R, Q) = \text{DENY} \implies \mathcal{C}_R \cap \text{Tokens}(\text{Body}(\text{Resp}(P, Q_R, S))) = \emptyset$$

**Interpretation:**
If the ground-truth authorization oracle asserts that Principal $P$ is denied access to Resource $R$, then regardless of whether the cache proxy $\mathcal{M}$ returns an HTTP 200, 304, 403, or 500, the body of the response must contain **zero** confidential canary tokens associated with Resource $R$.

### 1.2 The Non-Public Isolation Invariant
If resource $R$ is not public ($\text{Visibility}_R \neq \text{Public}$):
1. **Cross-Tenant Invariant:** If $T_P \neq T_R$, then $\mathcal{A}(P, R, Q) = \text{DENY}$ unless explicit cross-tenant sharing is defined.
2. **Cross-User Invariant:** If $\text{Visibility}_R = \text{UserPrivate}$ and $U_P \neq \text{Owner}_R$, then $\mathcal{A}(P, R, Q) = \text{DENY}$.
3. **Revocation Invariant:** If principal $P$'s access to $R$ was revoked at time $t_{\text{revoke}}$, then for all subsequent requests $t > t_{\text{revoke}}$, $\mathcal{A}(P, R, Q) = \text{DENY}$.

---

## 2. Differential Testing Workflow

The TenantCache differential engine operates across pairs of principals and permutations of cache states:

```
                      [ Initialize Lab & Seed Data ]
                                    │
                                    ▼
                      [ For each Target Resource R ]
                                    │
           ┌────────────────────────┴────────────────────────┐
           ▼                                                 ▼
   [ Symmetrical Cross-Tenant ]                      [ Stateful Revocation ]
  P_A (Tenant A) → P_B (Tenant B)                   P_A accesses R (Cold)
           │                                                 │
  Step 1: P_A queries R (Cold Cache)                Step 1: Cache Warmed (200 OK)
  Step 2: Inspect Cache Status (MISS)                        │
  Step 3: P_B queries R (Warm Cache)                Step 2: Invalidate Perm in DB
  Step 4: Inspect Cache Status (HIT/MISS)                    │
           │                                        Step 3: P_A re-queries R (Cache)
           ▼                                                 │
  [ Compare with Ground-Truth Oracle A(P_B, R) ]             ▼
           │                                        [ Compare with Oracle A(P_A, R) ]
           ▼                                                 │
  [ Scan Response Body for Canaries C_R ]                    ▼
           │                                        [ Scan Response for Canaries C_R ]
           ▼                                                 │
┌────────────────────────────────────────────────────────────┴─────────────────┐
│                           EVALUATION & CLASSIFICATION                        │
│   • Canary Detected AND A(P, R) = DENY  ===> CONFIRMED VULNERABILITY (LEAK)  │
│   • Canary Detected AND A(P, R) = ALLOW ===> LEGITIMATE ACCESS               │
│   • No Canary AND A(P, R) = DENY        ===> SECURE ENFORCEMENT              │
│   • Cache Hit on Public Resource        ===> BENIGN CACHE HIT (NO FP)        │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Canary Generation and Taint Attribution

To eliminate false positives caused by generic JSON keys, formatting similarities, or localized strings, TenantCache generates cryptographically unique canaries for every confidential field:

$$\text{Canary}(R, \text{field}) = \text{"TC\_CANARY\_"} \parallel \text{UUID4()}_{\text{hex}} \parallel \text{"\_"} \parallel \text{CRC32}(T_R \parallel R.\text{id})$$

When an unauthorized response body is received:
1. The scanner scans for all known canaries across the active universe of resources.
2. If a canary matching Resource $R$ is detected in a response served to Principal $P$ where $\mathcal{A}(P, R) = \text{DENY}$, the leak is attributed with **100% mathematical certainty** to the owner $T_R$ and Resource $R$.
3. The exact leak path (e.g., Cross-Tenant, Cross-User, or Post-Revocation) is recorded alongside HTTP request headers, response headers, and proxy cache-status indicators.

---

## 4. Cache State Control & Mutation Matrix

The testing engine controls and observes cache states through four deterministic operations:
1. **Cold State Initialization ($S_{\text{cold}}$):** Purging the cache volume or issuing unique cache-busting identifiers to ensure a guaranteed cache miss.
2. **Warm State Transition ($S_{\text{warm}}$):** Executing a legitimate authorized request to prime the intermediate proxy cache.
3. **Differential Execution ($S_{\text{probe}}$):** Executing the probe request under the alternate principal identity.
4. **Stateful Revocation ($S_{\text{revoked}}$):** Directly mutating application database state (e.g., deleting a role or access-grant record) without informing the reverse proxy, then immediately querying the proxy to measure revocation lag.
