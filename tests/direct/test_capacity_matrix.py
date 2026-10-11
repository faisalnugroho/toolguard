"""Boundary and complete public-state snapshots for active admission."""
import json
import pytest
from gltest.direct.loader import create_address
from test_toolguard import MANIFEST, MANIFEST_URL, POLICY, POLICY_URL, TOOL0_URL, TOOL1_URL, TOOL_WEATHER, TOOL_READ_CLEAN, sha, warp, resolve
from test_final_adversarial import capacity, open_unique, unique_tools, record, public_snapshot


@pytest.fixture
def c(direct_deploy):
    return direct_deploy('contracts/toolguard.py')


def test_one_available_slot_then_zero_available_slot(c, direct_vm):
    for owner_i in range(19):
        for slot in range(5):
            open_unique(c, direct_vm, owner_i, slot)
    assert capacity(c)["active"] == 95
    open_unique(c, direct_vm, 19, 0)
    assert capacity(c)["active"] == 96
    open_unique(c, direct_vm, 19, 1)
    open_unique(c, direct_vm, 19, 2)
    open_unique(c, direct_vm, 19, 3)
    assert capacity(c)["active"] == 99
    # Exactly one slot is available here.
    open_unique(c, direct_vm, 20, 0)
    assert capacity(c)["active"] == 100
    before = public_snapshot(c)
    with direct_vm.prank(create_address("boundary-overflow")):
        with direct_vm.expect_revert("active_capacity_full"):
            c.open_audit("boundary-overflow", "Boundary audit", MANIFEST_URL,
                         sha("boundary-manifest"), POLICY_URL,
                         sha("boundary-policy"), unique_tools("boundary"), 300)
    assert public_snapshot(c) == before


def test_failed_open_and_early_resolve_preserve_complete_public_state(c, direct_vm):
    open_unique(c, direct_vm, 0, 0)
    before = public_snapshot(c)
    with direct_vm.expect_revert("invalid_digest"):
        c.open_audit("bad-boundary", "Boundary audit", MANIFEST_URL,
                     "bad", POLICY_URL, sha(POLICY), unique_tools("bad"), 300)
    assert public_snapshot(c) == before
    with direct_vm.prank(create_address("final-owner-0")):
        with direct_vm.expect_revert("challenge_period_active"):
            c.resolve("final-0-0")
    assert public_snapshot(c) == before


def test_resolve_release_and_repeated_resolution_public_snapshot(c, direct_vm):
    open_unique(c, direct_vm, 0, 0)
    warp(direct_vm)
    with direct_vm.prank(create_address("final-owner-0")):
        resolve(c, direct_vm, aid="final-0-0")
    after_first = public_snapshot(c)
    assert after_first["capacity"]["active"] == 0
    with direct_vm.prank(create_address("final-owner-0")):
        with direct_vm.expect_revert("already_resolved"):
            c.resolve("final-0-0")
    assert public_snapshot(c) == after_first


def test_active_records_equal_reported_count_after_cycles(c, direct_vm):
    for i in range(5):
        open_unique(c, direct_vm, i, 0)
    assert sum(record(c, aid)["status"] == "OPEN" for aid in json.loads(c.list_audits())) == capacity(c)["active"]
    warp(direct_vm)
    for i in range(5):
        with direct_vm.prank(create_address("final-owner-%d" % i)):
            resolve(c, direct_vm, aid="final-%d-0" % i)
        actual = sum(record(c, aid)["status"] == "OPEN" for aid in json.loads(c.list_audits()))
        assert actual == capacity(c)["active"]
