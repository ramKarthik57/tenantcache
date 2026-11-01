# TenantCache Development Log

## Day 1: Project Conception, Research Foundation & Architecture
- **Environment Inspection:** Windows 10/11 workstation, Python 3.14.7, Git 2.53, Docker unavailable on local PATH. Confirmed requirement for dual-mode execution (Docker Compose definitions + high-fidelity native ASGI/HTTP cache simulation).
- **Literature Review Completed:** Reviewed RFC 9111, RFC 9110, USENIX Security '20 & '24 (Mirheidari et al., Nguyen et al.), Black Hat '18 & '20 (Kettle), IEEE S&P '17 & '21 (NEZHA, Calzavara et al.), OWASP BOLA, Autorize. Documented in `docs/LITERATURE_REVIEW.md`.
- **Comparative Analysis & Research Gap:** Documented existing tools taxonomy, limitations of stateless DAST scanners, and the multi-tenant caching disconnect in `docs/RELATED_WORK.md` and `docs/RESEARCH_GAP.md`.
- **Novelty Assessment & Methodology:** Formulated the formal security invariant $\mathcal{A}(P, R, Q) = \text{DENY} \implies \mathcal{C}_R \cap \text{Tokens}(\text{Body}) = \emptyset$, threat models, and research questions in `docs/NOVELTY_ASSESSMENT.md`, `docs/RESEARCH_QUESTIONS.md`, `docs/METHODOLOGY.md`, and `docs/THREAT_MODEL.md`.
- **Architecture Design:** Designed modular layers (`models`, `simulator`, `generator`, `cache`, `differential`, `oracle`, `detection`, `evaluation`, `reporting`, `cli`). Documented in `docs/ARCHITECTURE.md`.
- **Infrastructure Initialization:** Initialized project directory structure and created Architectural Decision Records (`docs/DECISIONS.md`).
