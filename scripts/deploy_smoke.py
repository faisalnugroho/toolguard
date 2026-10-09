#!/usr/bin/env python3
"""Deploy ToolGuard to Studionet + live consensus smoke test.

Adapted from the LinguaCert known-good deploy script (template:
deploy_smoke_studionet.py). Usage:
  ~/genlayer-env/bin/python scripts/deploy_smoke.py > smoke.log 2>&1
Requires a gitignored keyfile scripts/smoke_deployer.json with
{"address": ..., "private_key": "0x..."}.

PREREQUISITE: COMMIT below must be the pushed HEAD of this repo with the
examples/ files live at raw.githubusercontent.com — verify with the curl
pre-flight before running (it aborts on any mismatch).
"""
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

from genlayer_py import create_client, create_account
from genlayer_py.chains import studionet
from genlayer_py.types import TransactionStatus

# ---------------- CONFIG ----------------
CODE_PATH = Path("contracts/toolguard.py")
KEYFILE = Path("scripts/smoke_deployer.json")   # gitignored!
RAW = ("https://raw.githubusercontent.com/faisalnugroho/toolguard/"
       "{commit}/examples/")
DETERMINISM_RUNS = 3
CHALLENGE = 300      # 5 min challenge window for the smoke (min allowed)
CHALLENGE_WAIT = 320  # seconds to sleep after opens before resolving
# ----------------------------------------

log = {}


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def pinned(commit, name):
    url = RAW.format(commit=commit) + name
    assert len(url) <= 400
    return url


def load_account():
    data = json.loads(KEYFILE.read_text())
    return create_account(account_private_key=data["private_key"])


def wait_final(client, tx_hash, label, strict=True):
    """FINALIZED wait gating on BOTH consensus vote and leader execution.

    `result_name` is the consensus VOTE, never the exec result. A
    DISAGREE/NO_MAJORITY round finalizes but DISCARDS the state change —
    with strict=False the caller may re-crank the SAME audit id.
    """
    receipt = client.wait_for_transaction_receipt(
        transaction_hash=tx_hash,
        status=TransactionStatus.FINALIZED,
        retries=100,
        interval=3000,
    )
    if isinstance(receipt, dict):
        data = receipt.get("data") or {}
        addr = (data.get("contract_address")
                if isinstance(data, dict) else None)
        if addr is None:
            addr = receipt.get("to_address")
        leader = (receipt.get("consensus_data") or {}).get(
            "leader_receipt", [{}])
        lead = leader[0] if leader else {}
        exec_result = lead.get("execution_result")
        vote_result = receipt.get("result_name") or "UNKNOWN"
        if receipt.get("tx_execution_result_name") is not None:
            exec_result = receipt["tx_execution_result_name"]
        stderr = str((lead.get("genvm_result") or {}).get("stderr") or "")
    else:
        addr = getattr(receipt, "contract_address", None)
        exec_result = None
        vote_result = "UNKNOWN"
        stderr = ""
    ok = (exec_result in (None, "SUCCESS", "FINISHED_WITH_RETURN")
          and vote_result in ("MAJORITY_AGREE", None))
    print(f"[{label}] FINALIZED vote={vote_result} exec={exec_result} "
          f"ok={ok}", flush=True)
    if not ok:
        print("CONSENSUS/EXECUTION FAILED:")
        print(json.dumps(receipt.get("consensus_data"), default=str)[:2000])
        if stderr:
            print("STDERR tail:", stderr[-1500:])
        if strict:
            raise RuntimeError(
                f"{label} failed: vote={vote_result} exec={exec_result}")
        print(f"[{label}] state change discarded — record remains unresolved")
    return {"execution_result": exec_result or "SUCCESS",
            "vote_result": vote_result, "ok": ok,
            "contract_address": addr, "stderr_tail": stderr[-1500:]}


def preflight(commit, files):
    """Every pinned URL must exist AT the pinned commit and byte-match the
    local file. A stale pin 404s on-chain -> fail-safe INCONCLUSIVE burns a
    consensus round."""
    bad = []
    for name in files:
        url = pinned(commit, name)
        out = subprocess.run(["curl", "-s", "-w", "%{http_code}", "-o", "/tmp/tg_pf.tmp", url],
                             capture_output=True, text=True).stdout
        status = out[-3:]
        local = Path("examples", name).read_bytes()
        if status != "200" or Path("/tmp/tg_pf.tmp").read_bytes() != local:
            bad.append((name, status))
    if bad:
        print("PREFLIGHT FAILED (stale pin or content mismatch):", bad)
        sys.exit(1)
    print("preflight ok:", len(files), "files byte-match at commit", commit)


def main():
    account = load_account()
    client = create_client(chain=studionet, account=account)
    print("deployer:", account.address, flush=True)

    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True
    ).stdout.strip()
    if len(commit) != 40:
        raise SystemExit("git rev-parse failed — run inside the repo")
    files = ["clean-server/manifest.json", "clean-server/get_weather.json",
             "clean-server/read_file.json", "poisoned-server/manifest.json",
             "poisoned-server/get_weather.json", "poisoned-server/read_file.json",
             "policy.md"]
    preflight(commit, files)

    code = CODE_PATH.read_text()
    tx = client.deploy_contract(code=code, account=client.local_account,
                                args=[], leader_only=True)
    res = wait_final(client, tx, "deploy")
    addr = res["contract_address"]
    log["deploy"] = {"tx_hash": tx, "address": addr, "commit": commit,
                     "code_sha256": hashlib.sha256(
                         code.encode()).hexdigest()}
    print("CONTRACT:", addr)
    print("explorer: https://explorer-studio.genlayer.com/address/" + addr)

    policy = Path("examples/policy.md").read_text()
    clean_manifest = Path("examples/clean-server/manifest.json").read_text()
    poisoned_manifest = Path(
        "examples/poisoned-server/manifest.json").read_text()

    def tools_json(server_dir):
        tools = []
        for name in ("get_weather.json", "read_file.json"):
            body = Path("examples", server_dir, name).read_text()
            # v1.2: each entry canonically binds the descriptor's tool NAME
            # to its pinned digest (checked again at resolve).
            tool_name = json.loads(body).get("name") or name[:-5]
            tools.append({"name": tool_name,
                          "url": pinned(commit, f"{server_dir}/{name}"),
                          "digest": sha(body)})
        return json.dumps(tools)

    audits = [
        # v1.1-comparability rows (clean TRUSTED x3, poison FLAGGED x1)
        ("smoke-clean-1", "Clean MCP server (2 tools)", "clean-server",
         clean_manifest, "TRUSTED"),
        ("smoke-clean-2", "Clean MCP server (2 tools)", "clean-server",
         clean_manifest, "TRUSTED"),
        ("smoke-clean-3", "Clean MCP server (2 tools)", "clean-server",
         clean_manifest, "TRUSTED"),
        ("smoke-poison-1", "Poisoned MCP server (exfil tool)",
         "poisoned-server", poisoned_manifest, "FLAGGED"),
        # v1.2 lifecycle rows: the SAME poisoned bundle audited twice.
        # Row A genuinely flags (deterministic exfil content). Row B is the
        # competing-opinion slot: if the model rejudges SAFE it resolves
        # TRUSTED and the on-chain correction sweep fires; if it re-flags,
        # the row honestly records FLAGGED again (lifecycle_ok=False) —
        # the dispute sweep is consensus-gated, not script-guaranteed.
        # Deterministic coverage of the sweep lives in tests/direct.
        ("smoke-dispute-flag", "Poisoned server (dispute A)",
         "poisoned-server", poisoned_manifest, "FLAGGED"),
        ("smoke-dispute-trust", "Poisoned server (dispute B)",
         "poisoned-server", poisoned_manifest, "TRUSTED-or-FLAGGED"),
    ]

    # Phase 1: open every audit; challenge clocks run in parallel.
    for aid, title, server_dir, manifest, _ in audits:
        tx = client.write_contract(
            address=addr, function_name="open_audit",
            args=[aid, title,
                  pinned(commit, f"{server_dir}/manifest.json"),
                  sha(manifest),
                  pinned(commit, "policy.md"), sha(policy),
                  tools_json(server_dir), CHALLENGE],
            account=client.local_account)
        wait_final(client, tx, f"open#{aid}")
        log.setdefault("opens", {})[aid] = server_dir

    print(f"challenge window: sleeping {CHALLENGE_WAIT}s ...", flush=True)
    time.sleep(CHALLENGE_WAIT)

    # Phase 2: resolve every audit, read verdicts.
    verdicts = {}
    for aid, title, server_dir, manifest, expected in audits:
        for attempt in (1, 2, 3):
            t0 = time.time()
            tx = client.write_contract(
                address=addr, function_name="resolve",
                args=[aid], account=client.local_account)
            res = wait_final(client, tx, f"resolve#{aid}#a{attempt}",
                             strict=False)
            raw = client.read_contract(address=addr, function_name="get_audit",
                                       args=[aid])
            record = json.loads(raw if isinstance(raw, str) else str(raw))
            verdict = record["result"].get("verdict") if record.get(
                "result") else None
            secs = round(time.time() - t0, 1)
            print(f"{aid}: {verdict} [{secs}s] (attempt {attempt})",
                  flush=True)
            if record.get("status") == "RESOLVED":
                verdicts[aid] = verdict
                log[aid] = {"server": server_dir, "expected": expected,
                            "verdict": verdict, "secs": secs,
                            "consensus_rounds": attempt,
                            "result": record["result"]}
                break
        else:
            verdicts[aid] = "UNRESOLVED"
            log[aid] = {"server": server_dir, "expected": expected,
                        "verdict": "UNRESOLVED", "consensus_rounds": 3}

    clean_results = [verdicts[a[0]] for a in audits
                     if a[0].startswith("smoke-clean")]
    ok_det = (len(clean_results) == 3 and
              len(set(clean_results)) == 1 and clean_results[0] == "TRUSTED")
    poison_verdict = verdicts.get("smoke-poison-1")

    dispute_flag = verdicts.get("smoke-dispute-flag")
    dispute_trust = verdicts.get("smoke-dispute-trust")
    lifecycle_ok = (dispute_flag == "FLAGGED" and dispute_trust == "TRUSTED")
    log["results"] = {
        "determinism_consistent": ok_det,
        "clean_verdicts": clean_results,
        "poison_verdict": poison_verdict,
        "poison_flagged_as_expected": poison_verdict == "FLAGGED",
        "dispute_flag_verdict": dispute_flag,
        "dispute_trust_verdict": dispute_trust,
        "dispute_lifecycle_ok": lifecycle_ok,
    }
    Path("docs/deployment_log.json").write_text(json.dumps(log, indent=2))
    print("DETERMINISM_CONSISTENT:", ok_det)
    print("POISON_FLAGGED:", poison_verdict == "FLAGGED")
    print("DISPUTE_ROWS:", dispute_flag, "->", dispute_trust,
          "(sweep fired)" if lifecycle_ok else "(no verdict divergence)")
    print("DONE. contract:", addr)


if __name__ == "__main__":
    main()
