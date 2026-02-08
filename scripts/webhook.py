#!/usr/bin/env python3
"""Send webhook notifications for pipeline lifecycle events.

This script dispatches signed HTTP POST requests to a configured webhook
URL at key points in the pipeline lifecycle.  Payloads are JSON-encoded
and optionally signed with HMAC-SHA256 using a shared secret, following
the same pattern as GitHub webhook deliveries.

Supported events
----------------
scan_started
    Fired after the target repo is cloned and before CodeQL analysis begins.
scan_completed
    Fired after SARIF parsing is complete, with issue and batch counts.
session_created
    Fired each time a Devin session is successfully created.

Environment variables
---------------------
WEBHOOK_URL : str
    HTTP(S) endpoint to receive webhook payloads.
WEBHOOK_SECRET : str
    Optional shared secret for HMAC-SHA256 payload signing.
"""

import argparse
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone

import requests


def _sign_payload(payload: bytes, secret: str) -> str:
    return "sha256=" + hmac.new(
        secret.encode(), payload, hashlib.sha256
    ).hexdigest()


def send_webhook(
    url: str,
    event: str,
    data: dict,
    secret: str = "",
    timeout: int = 10,
) -> bool:
    payload = json.dumps(
        {
            "event": event,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **data,
        },
        indent=2,
    ).encode()

    headers = {
        "Content-Type": "application/json",
        "X-CodeQL-Fixer-Event": event,
    }
    if secret:
        headers["X-Hub-Signature-256"] = _sign_payload(payload, secret)

    for attempt in range(3):
        try:
            resp = requests.post(url, data=payload, headers=headers, timeout=timeout)
            if resp.status_code < 400:
                print(f"Webhook '{event}' delivered ({resp.status_code})")
                return True
            print(f"Webhook '{event}' failed ({resp.status_code}): {resp.text[:200]}")
        except requests.exceptions.RequestException as e:
            print(f"Webhook '{event}' error (attempt {attempt + 1}/3): {e}")
        if attempt < 2:
            time.sleep(2 ** attempt)

    print(f"WARNING: Webhook '{event}' delivery failed after 3 attempts")
    return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Send pipeline webhook")
    parser.add_argument("--event", required=True, choices=[
        "scan_started", "scan_completed", "session_created",
        "fix_verified", "objective_met", "sla_breach", "cycle_completed",
    ])
    parser.add_argument("--target-repo", default="")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--total-issues", default="")
    parser.add_argument("--total-batches", default="")
    parser.add_argument("--session-id", default="")
    parser.add_argument("--session-url", default="")
    parser.add_argument("--batch-id", default="")
    args = parser.parse_args()

    url = os.environ.get("WEBHOOK_URL", "")
    if not url:
        print("No WEBHOOK_URL set; skipping webhook")
        return

    secret = os.environ.get("WEBHOOK_SECRET", "")

    data: dict = {}
    if args.target_repo:
        data["target_repo"] = args.target_repo
    if args.run_id:
        data["run_id"] = args.run_id

    if args.event == "scan_completed":
        if args.total_issues:
            data["total_issues"] = int(args.total_issues)
        if args.total_batches:
            data["total_batches"] = int(args.total_batches)
    elif args.event == "session_created":
        if args.session_id:
            data["session_id"] = args.session_id
        if args.session_url:
            data["session_url"] = args.session_url
        if args.batch_id:
            data["batch_id"] = args.batch_id

    send_webhook(url, args.event, data, secret)


if __name__ == "__main__":
    main()
