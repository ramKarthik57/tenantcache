# Contributing to TenantCache

Thank you for your interest in contributing to **TenantCache**! We welcome contributions from researchers, security engineers, and systems developers.

---

## 1. Development Principles & Code Standards

TenantCache is an academic cybersecurity verification framework. Every contribution must adhere to strict principles:

- **Mathematical Determinism:** Verification outcomes across identical seeds must be 100% reproducible ($\sigma = 0.0000$).
- **Fail-Closed Security:** Any unverified attribute, unrecognized principal, or ambiguous route must fail closed (`AuthDecision.DENY` or `403/404`).
- **Zero Unsolicited Complexity:** We do not introduce heavy third-party enterprise databases or external SaaS dependencies. The system runs offline via localhost loopback.
- **Python Compatibility:** Code must support Python >= 3.11 (tested on 3.11, 3.12, 3.14).

---

## 2. Local Environment Setup

```bash
# 1. Clone repository
git clone https://github.com/ramKarthik57/tenantcache.git
cd tenantcache

# 2. Create isolated virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\Activate.ps1

# 3. Install dependencies from locked constraints
pip install -r constraints.txt
pip install -e ".[dev]"  # Editable install with test dependencies

# 4. Run environment doctor check
tenantcache doctor
```

---

## 3. Testing Requirements

Every Pull Request must pass the complete automated test suite before merge:

```bash
# 1. Run core test suite (37 tests, fast offline)
pytest tests/ -v --ignore=tests/unit/test_property_hypothesis.py

# 2. Run property-based invariant suite (requires Hypothesis)
pytest tests/unit/test_property_hypothesis.py -v

# 3. Run native Nginx integration suite (requires local Nginx)
pytest tests/integration/test_real_nginx.py -v

# 4. Verify benchmark invariants
python -m tenantcache.cli benchmark --version v1.1 --profile comprehensive
```

---

## 4. Coding Conventions & Pull Request Guidelines

1. **Commit Messages:** Follow [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat(...)`: New feature or archetype
   - `fix(...)`: Bug fix or security correction
   - `docs(...)`: Documentation or paper update
   - `test(...)`: Adding or refining test cases
   - `ci(...)`: Workflow or packaging update
2. **Type Annotations:** All new Python functions must include complete typing annotations (`typing.Dict`, `Optional`, `List`).
3. **No Generated Residue:** Ensure no `.pyc`, `.log`, or cache entries are committed. Use `scripts/build_release_zip.py` for packaging.
4. **Issue Linking:** Reference related GitHub issues in your PR description (e.g., `Closes #12`).
