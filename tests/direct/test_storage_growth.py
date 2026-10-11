import json, time, sys
sys.path.insert(0, 'tests/direct')
from test_final_adversarial import open_unique
import pytest

@pytest.fixture
def c(direct_deploy):
    return direct_deploy('contracts/toolguard.py')


def capacity(c):
    return json.loads(c.get_capacity())


# Benchmark only the actual contract admission path; no deployment or network write.



def test_measure(direct_deploy, direct_vm):
    c=direct_deploy('contracts/toolguard.py')
    t0=time.perf_counter()
    for owner in range(20):
        for slot in range(5):
            open_unique(c, direct_vm, owner, slot)
    elapsed=time.perf_counter()-t0
    ids=c.list_audits()
    audits=[c.get_audit(a) for a in json.loads(ids)]
    cap=c.get_capacity(); stats=c.get_stats()
    print('BENCH open100_seconds=%.6f ids_bytes=%d audits_bytes=%d capacity_bytes=%d stats_bytes=%d total_public_bytes=%d' % (elapsed,len(ids.encode()),sum(len(x.encode()) for x in audits),len(cap.encode()),len(stats.encode()),len(ids.encode())+sum(len(x.encode()) for x in audits)+len(cap.encode())+len(stats.encode())))
