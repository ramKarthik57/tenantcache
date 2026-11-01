"""Differential Testing Engine: Coordinates sequences across identities and cache states."""

import time
import httpx
import warnings
from typing import List, Optional, Dict, Any

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from starlette.testclient import TestClient
from src.tenantcache.models import (
    RequestSpec, ResponseRecord, Finding, CacheStatus, Principal, Resource
)
from src.tenantcache.cache import ProxyCacheSimulator
from src.tenantcache.oracle import SecurityOracle
from src.tenantcache.detection import LeakageDetector
from src.tenantcache.generator import TestSequence
from src.tenantcache.config import TargetSecurityGuard
from lab.application.main import app as lab_fastapi_app


class DifferentialRunner:
    """Executes differential security sequences against a simulated or live HTTP cache proxy."""

    def __init__(
        self,
        oracle: SecurityOracle,
        detector: LeakageDetector,
        cache_simulator: Optional[ProxyCacheSimulator] = None,
        live_base_url: Optional[str] = None
    ):
        if live_base_url:
            TargetSecurityGuard.validate_target_url(live_base_url)
        self.oracle = oracle
        self.detector = detector
        self.cache_sim = cache_simulator or ProxyCacheSimulator(config_archetype="V1_MISSING_TENANT_KEY")
        self.live_base_url = live_base_url
        self.findings: List[Finding] = []
        self.total_requests = 0
        self._test_client = TestClient(lab_fastapi_app, base_url="http://localhost")

    def execute_request(self, request: RequestSpec) -> ResponseRecord:
        """Executes a single request through the cache proxy layer into the application backend."""
        self.total_requests += 1
        start_time = time.time()

        if self.live_base_url:
            # Live HTTP execution mode
            full_url = f"{self.live_base_url.rstrip('/')}{request.url_path}"
            with httpx.Client(timeout=5.0) as client:
                res = client.request(
                    method=request.method,
                    url=full_url,
                    headers=request.headers,
                    params=request.query_params
                )
                status_code = res.status_code
                headers = dict(res.headers)
                body_text = res.text
                cache_status_raw = headers.get("X-Cache-Status", "UNKNOWN").upper()
                try:
                    cache_status = CacheStatus(cache_status_raw)
                except ValueError:
                    cache_status = CacheStatus.UNKNOWN

        else:
            # High-fidelity In-Memory ASGI + ProxyCacheSimulator mode
            # 1. Lookup in Cache Simulator
            cached_resp = self.cache_sim.lookup(request)
            if cached_resp:
                cached_resp.latency_ms = (time.time() - start_time) * 1000.0
                return cached_resp

            # 2. Cache MISS: Forward request to FastAPI Lab Application via TestClient
            res = self._test_client.request(
                method=request.method,
                url=request.url_path,
                headers=request.headers,
                params=request.query_params
            )
            status_code = res.status_code
            headers = dict(res.headers)
            body_text = res.text

            # Store response in cache simulator
            self.cache_sim.store(request, status_code, headers, body_text)
            cache_status = CacheStatus.MISS
            headers["X-Cache-Status"] = "MISS"

        latency = (time.time() - start_time) * 1000.0
        return ResponseRecord(
            status_code=status_code,
            headers=headers,
            body_text=body_text,
            cache_status=cache_status,
            latency_ms=latency
        )

    def run_sequence(self, sequence: TestSequence, on_revocation_hook: Optional[Any] = None) -> List[Finding]:
        """Executes an ordered differential test sequence."""
        sequence_findings = []

        # Reset cache before sequence for deterministic cold start
        self.cache_sim.purge_all()

        for step_idx, (step_desc, req_spec) in enumerate(sequence.steps):
            # Special handling for revocation tests: mutate origin database right before post-revocation probe
            if "post_revocation_probe" in req_spec.step_name and on_revocation_hook:
                on_revocation_hook(sequence.resource.id, req_spec.principal.user_id)

            resp_record = self.execute_request(req_spec)

            # Evaluate with leakage detector on probe steps
            if "probe" in req_spec.step_name:
                finding = self.detector.evaluate_response(
                    principal=req_spec.principal,
                    target_resource=sequence.resource,
                    response=resp_record,
                    step_name=req_spec.step_name,
                    sequence_category=sequence.category
                )
                if finding:
                    sequence_findings.append(finding)
                    self.findings.append(finding)

        return sequence_findings
