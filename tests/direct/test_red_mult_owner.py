import hashlib
import json
import sys
from gltest.direct.loader import create_address

OWNER = 'https://raw.githubusercontent.com/example/mcp-servers/' + 'b' * 40 + '/'
MANIFEST_URL = OWNER + 'doc0.json'
POLICY_URL = OWNER + 'doc1.md'
TOOL0_URL = OWNER + 'doc2.json'
TOOL1_URL = OWNER + 'doc3.json'

def sha(x):
    return hashlib.sha256(x.encode()).hexdigest()

def test_red_multi_owner_exhaustion(direct_deploy, direct_vm):
    c = direct_deploy('contracts/toolguard.py')
    tools = json.dumps([
        {'name':'get_weather','url':TOOL0_URL,'digest':sha('tool0')},
        {'name':'read_file','url':TOOL1_URL,'digest':sha('tool1')},
    ])
    for owner_i in range(20):
        with direct_vm.prank(create_address('owner-%d' % owner_i)):
            for slot in range(5):
                suffix = '%d-%d' % (owner_i, slot)
                c.open_audit('exhaust-%s' % suffix, 'Multi owner audit',
                    MANIFEST_URL, sha('manifest-' + suffix),
                    POLICY_URL, sha('policy-' + suffix),
                    json.dumps([
                      {'name':'get_weather','url':TOOL0_URL,'digest':sha('tool0-'+suffix)},
                      {'name':'read_file','url':TOOL1_URL,'digest':sha('tool1-'+suffix)}]), 300)
    with direct_vm.prank(create_address('owner-overflow')):
      with direct_vm.expect_revert('active_capacity_full'):
        c.open_audit('exhaust-overflow', 'Multi owner audit', MANIFEST_URL,
            sha('manifest-overflow'), POLICY_URL, sha('policy-overflow'),
            json.dumps([
              {'name':'get_weather','url':TOOL0_URL,'digest':sha('tool0-overflow')},
              {'name':'read_file','url':TOOL1_URL,'digest':sha('tool1-overflow')}]), 300)
