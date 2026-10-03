#!/usr/bin/env python3
"""ToolGuard live demo recording: full poisoned-server audit in the real dApp.
Opens a REAL on-chain audit from the UI (burner wallet), waits out the
challenge countdown visually, resolves from the UI, and shows the FLAGGED
verdict + verbatim citations + on-chain audit list. Saves slow screenshots
for ffmpeg assembly + a full-speed webm (backup).
"""
import time
from pathlib import Path
from playwright.sync_api import sync_playwright

OUT = Path("/home/ubuntu/toolguard/artifacts/demo_shots"); OUT.mkdir(parents=True, exist_ok=True)
URL = "https://faisalnugroho.github.io/toolguard/"
AID = "demo-poisoned-" + time.strftime("%H%M%S")
SHOT = lambda name: str(OUT / f"{name}.png")

def ts(page, name, hold=3.0):
    page.screenshot(path=SHOT(name))
    (OUT / f"{name}.hold").write_text(str(hold))
    print("shot:", name, flush=True)

with sync_playwright() as p:
    b = p.chromium.launch(headless=True)
    pg = b.new_page(viewport={"width":1280,"height":800}, record_video_dir=str(OUT/"video"),
                    record_video_size={"width":1280,"height":800})
    pg.set_default_timeout(30000)
    pg.goto(URL, wait_until="networkidle")
    pg.wait_for_selector("#statsBox .stats", timeout=30000)
    ts(pg, "01-home", 3.0)

    # go to the audit runner
    pg.click("a[href='#/run']")
    pg.wait_for_selector("[data-demo='poisoned']")
    ts(pg, "02-run", 2.0)

    # pick the poisoned server
    pg.click("[data-demo='poisoned']")
    pg.wait_for_function("document.querySelector('#manifestDigest').textContent.length === 64", timeout=30000)
    pg.fill("#auditId", AID)
    ts(pg, "03-poisoned-form", 3.0)

    # open the audit on-chain (burner created + faucet + write)
    pg.click("#openBtn")
    pg.wait_for_function(
        "document.querySelector('#openOut').textContent.includes('Audit opened')",
        timeout=180000)
    ts(pg, "04-opened", 3.5)

    # wait out the challenge countdown visually (300s -> film the ready state)
    pg.wait_for_function(
        "document.querySelector('#cd').textContent.includes('ready to resolve')",
        timeout=330000, polling=1000)
    pg.wait_for_timeout(1500)
    ts(pg, "05-countdown-done", 2.0)

    # resolve from the UI (real consensus, 45-90s)
    pg.click("#resolveBtn")
    pg.wait_for_function(
        "document.querySelector('#resolveOut').textContent.includes('Resolved')",
        timeout=420000)
    pg.wait_for_timeout(2500)  # page navigates to the audit record
    pg.wait_for_selector(".stamp", timeout=60000)
    pg.wait_for_timeout(800)
    ts(pg, "06-verdict", 5.0)

    # full record view: citations
    pg.screenshot(path=SHOT("07-verdict-top"), full_page=True)
    (OUT / "07-verdict-top.hold").write_text("3.0")
    print("shot: 07-verdict-top", flush=True)

    # on-chain audits list: TRUSTED + FLAGGED rows together
    pg.click("a[href='#/audits']")
    pg.wait_for_selector("#auditsBox table", timeout=30000)
    pg.wait_for_timeout(1200)
    ts(pg, "08-audits", 3.0)

    # explorer: the audit record is public on-chain evidence
    pg.goto("https://explorer-studio.genlayer.com/address/0x2937bf603e4E599a98400ed94fe3568264d1D63b",
            wait_until="domcontentloaded")
    pg.wait_for_timeout(9000)
    ts(pg, "09-explorer", 3.0)

    # keep the backup webm
    video = pg.video
    b.close()
    if video:
        try:
            path = video.path()
            Path(path).rename(OUT / "toolguard-demo-backup.webm")
            print("backup webm saved", flush=True)
        except Exception as e:
            print("webm move failed (page closed first):", e, flush=True)

print("AID:", AID)
print("DONE")
