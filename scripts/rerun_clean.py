#!/usr/bin/env python3
"""Re-audit the improved clean-server build on the SAME deployed contract.

The v1.1 smoke honestly sealed the original clean build INCONCLUSIVE x3 (validators consistently judged the path-unrestricted read_file descriptor
borderline under policy R3). This script opens THREE fresh audits with the
tightened descriptors (explicit user-picked file + workspace-only
restriction) and expects TRUSTED x3. Contract unchanged - no redeploy.
Appends to docs/deployment_log.json (merge, never overwrite).
"""
import hashlib
import json
import subprocess
import time
from pathlib import Path

from genlayer_py import create_client, create_account
from genlayer_py.chains import studionet
from genlayer_py.types import TransactionStatus

KEYFILE = Path("scripts/smoke_deployer.json")
CONTRACT = "0xe31d825A2E610d115dE86B2E2e53b0ECBDAa36A2"
RAW = ("https://raw.githubusercontent.com/faisalnugroho/toolguard/"
       "{commit}/examples/")
CHALLENGE = 300
CHALLENGE_WAIT = 320


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def pinned(commit, name):
    return RAW.format(commit=commit) + name


def wait_final(client, tx_hash, label, strict=True):
    receipt = client.wait_for_transaction_receipt(
        transaction_hash=tx_hash, status=TransactionStatus.FINALIZED,
        retries=100, interval=3000)
    leader = (receipt.get("consensus_data") or {}).get("leader_receipt", [{}])
    lead = leader[0] if leader else {}
    exec_result = lead.get("execution_result")
    vote_result = receipt.get("result_name") or "UNKNOWN"
    if receipt.get("tx_execution_result_name") is not None:
        exec_result = receipt["tx_execution_result_name"]
    ok = (exec_result in (None, "SUCCESS", "FINISHED_WITH_RETURN")
          and vote_result in ("MAJORITY_AGREE", None))
    print(f"[{label}] vote={vote_result} exec={exec_result} ok={ok}",
          flush=True)
    if not ok and strict:
        raise RuntimeError(f"{label} failed")
    return ok


def main():
    account = create_account(account_private_key=json.loads(
        KEYFILE.read_text())["private_key"])
    client = create_client(chain=studionet, account=account)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True,
                            text=True).stdout.strip()
    print("commit:", commit, flush=True)

    # pre-flight: every pinned URL byte-matches at the pinned commit
    for name in ("clean-server/manifest.json",
                 "clean-server/get_weather.json",
                 "clean-server/read_file.json", "policy.md"):
        out = subprocess.run(
            ["curl", "-s", "-w", "%{http_code}", "-o", "/tmp/tg_pf2.tmp",
             pinned(commit, name)], capture_output=True, text=True).stdout
        if out[-3:] != "200" or Path("/tmp/tg_pf2.tmp").read_bytes() != Path(
                "examples", name).read_bytes():
            raise SystemExit(f"PREFLIGHT FAILED: {name} ({out[-3:]})")
    print("preflight ok", flush=True)

    manifest = Path("examples/clean-server/manifest.json").read_text()
    policy = Path("examples/policy.md").read_text()
    tools = json.dumps([
        {"url": pinned(commit, "clean-server/get_weather.json"),
         "digest": sha(Path("examples/clean-server/get_weather.json").read_text())},
        {"url": pinned(commit, "clean-server/read_file.json"),
         "digest": sha(Path("examples/clean-server/read_file.json").read_text())},
    ])
    audits = [(f"smoke-clean-v2-{i}", "Clean MCP server v2 (restricted "
               "file reader)") for i in (1, 2, 3)]

    for aid, title in audits:
        tx = client.write_contract(
            address=CONTRACT, function_name="open_audit",
            args=[aid, title, pinned(commit, "clean-server/manifest.json"),
                  sha(manifest), pinned(commit, "policy.md"), sha(policy),
                  tools, CHALLENGE], account=client.local_account)
        wait_final(client, tx, f"open#{aid}")

    print(f"challenge window: sleeping {CHALLENGE_WAIT}s ...", flush=True)
    time.sleep(CHALLENGE_WAIT)

    log = json.loads(Path("docs/deployment_log.json").read_text())
    verdicts = []
    for aid, title in audits:
        for attempt in (1, 2, 3):
            tx = client.write_contract(
                address=CONTRACT, function_name="resolve", args=[aid],
                account=client.local_account)
            wait_final(client, tx, f"resolve#{aid}#a{attempt}", strict=False)
            raw = client.read_contract(address=CONTRACT,
                                       function_name="get_audit", args=[aid])
            rec = json.loads(raw if isinstance(raw, str) else str(raw))
            if rec.get("status") == "RESOLVED":
                verdict = rec["result"].get("verdict")
                print(f"{aid}: {verdict} (attempt {attempt})", flush=True)
                verdicts.append(verdict)
                log[aid] = {
                    "server": "clean-server (v2 restricted descriptors)",
                    "expected": "TRUSTED", "verdict": verdict,
                    "consensus_rounds": attempt, "result": rec["result"],
                    "correction_note": ("Re-audit of the improved clean build "
                                        "after the v2 smoke INCONCLUSIVE x3: "
                                        "validators consistently judged the "
                                        "original path-unrestricted read_file "
                                        "descriptor borderline under R3; the "
                                        "v2 descriptor states the explicit "
                                        "user-picked purpose and the "
                                        "workspace-only restriction.")}
                break
        else:
            verdicts.append("UNRESOLVED")

    log["results"]["clean_v2_verdicts"] = verdicts
    log["results"]["clean_v2_trusted_x3"] = (
        verdicts == ["TRUSTED", "TRUSTED", "TRUSTED"])
    Path("docs/deployment_log.json").write_text(json.dumps(log, indent=2))
    print("CLEAN_V2_TRUSTED_X3:",
          verdicts == ["TRUSTED", "TRUSTED", "TRUSTED"], flush=True)
    print("DONE", flush=True)


if __name__ == "__main__":
    main()
