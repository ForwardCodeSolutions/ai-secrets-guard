"""Probe runner: sends payloads to live endpoints and collects responses."""

from __future__ import annotations

import asyncio
import datetime as dt
import time
from typing import Any

import httpx

from ai_secrets_guard.core.config import ProbeConfig
from ai_secrets_guard.core.models import ProbeLog, ProbePayload, ProbeResponse, ProbeResult
from ai_secrets_guard.probe.judge import evaluate_response
from ai_secrets_guard.probe.payloads import get_all_payloads


async def run_probes(
    target_url: str,
    *,
    payloads: list[ProbePayload] | None = None,
    config: ProbeConfig | None = None,
    headers: dict[str, str] | None = None,
    judge_enabled: bool = True,
) -> ProbeResult:
    """Send all payloads to *target_url* and collect judge verdicts.

    - Concurrency is bounded by ``config.concurrent_requests`` (default 5).
    - A delay of ``config.delay_ms`` milliseconds is inserted between requests.
    - Custom *headers* are forwarded with every request.
    - Each request/response pair is captured in ``result.logs``.
    """
    config = config or ProbeConfig()
    payloads = payloads or get_all_payloads()
    result = ProbeResult(target_url=target_url)

    timeout = httpx.Timeout(float(config.timeout_seconds), connect=10.0)
    transport = httpx.AsyncHTTPTransport(retries=config.max_retries)
    semaphore = asyncio.Semaphore(config.concurrent_requests)
    delay_lock = asyncio.Lock()

    async with httpx.AsyncClient(
        timeout=timeout,
        transport=transport,
        headers=headers,
    ) as client:
        tasks = [
            _probe_single(
                client,
                target_url,
                payload,
                semaphore,
                config,
                judge_enabled,
                delay_lock,
            )
            for payload in payloads
        ]
        outcomes = await asyncio.gather(*tasks, return_exceptions=True)

        for outcome in outcomes:
            if isinstance(outcome, tuple):
                resp, log = outcome
                result.responses.append(resp)
                result.logs.append(log)

    result.finished_at = dt.datetime.now(dt.UTC)
    return result


async def _probe_single(
    client: httpx.AsyncClient,
    target_url: str,
    payload: ProbePayload,
    semaphore: asyncio.Semaphore,
    config: ProbeConfig,
    judge_enabled: bool,
    delay_lock: asyncio.Lock,
) -> tuple[ProbeResponse, ProbeLog]:
    async with semaphore:
        async with delay_lock:
            await asyncio.sleep(config.delay_ms / 1000.0)

        body: dict[str, object] = {
            "messages": payload.messages,
            "model": config.judge_model,
        }

        log = ProbeLog(
            payload_name=payload.name,
            request_url=target_url,
            request_headers=dict(client.headers),
            request_body=body,
        )

        start = time.monotonic()

        try:
            resp = await client.post(target_url, json=body)
            elapsed_ms = (time.monotonic() - start) * 1000

            log.response_status = resp.status_code
            log.response_headers = dict(resp.headers)
            log.duration_ms = elapsed_ms

            resp.raise_for_status()
            data = resp.json()
            raw_text = _extract_text(data)
            log.response_body = raw_text[:4000]
        except (httpx.HTTPError, Exception) as exc:
            elapsed_ms = (time.monotonic() - start) * 1000
            log.duration_ms = elapsed_ms
            log.error = str(exc)
            log.response_body = f"ERROR: {exc!s}"

            return (
                ProbeResponse(
                    payload_name=payload.name,
                    raw_response=f"ERROR: {exc!s}",
                    is_vulnerable=False,
                    judge_verdict=f"Probe failed: {exc!s}",
                    evidence="",
                    technique=payload.category,
                ),
                log,
            )

        verdict_text = ""
        is_vulnerable = False
        confidence = 0.0
        evidence = ""
        technique = payload.category

        if judge_enabled:
            last_user_msg = payload.messages[-1]["content"]
            verdict = await evaluate_response(
                last_user_msg,
                raw_text,
                model=config.judge_model,
                confidence_threshold=config.confidence_threshold,
            )
            is_vulnerable = verdict.is_vulnerable
            verdict_text = verdict.reasoning
            confidence = verdict.confidence
            evidence = verdict.evidence
            technique = verdict.technique or payload.category

        return (
            ProbeResponse(
                payload_name=payload.name,
                raw_response=raw_text[:2000],
                is_vulnerable=is_vulnerable,
                judge_verdict=verdict_text,
                judge_confidence=confidence,
                evidence=evidence,
                technique=technique,
            ),
            log,
        )


def _extract_text(data: dict[str, Any]) -> str:
    if "choices" in data:
        result: str = data["choices"][0].get("message", {}).get("content", "")
        return result
    if "content" in data:
        items = data["content"]
        if isinstance(items, list):
            return " ".join(c.get("text", "") for c in items if isinstance(c, dict))
        return str(items)
    if "response" in data:
        return str(data["response"])
    return str(data)
