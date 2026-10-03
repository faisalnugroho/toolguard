from pathlib import Path
from gltest.direct.sdk_loader import setup_sdk_paths
setup_sdk_paths(Path(__file__).resolve().parents[2] / 'contracts/toolguard.py')
