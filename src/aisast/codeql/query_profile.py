"""Materialize the current custom queries as an immutable per-scan snapshot."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml
from aisast.resources import scanner_root


def materialize_current_queries(output: Path) -> tuple[Path, dict]:
    root = scanner_root()
    profile_path = root / 'config/plan7/current-queries.json'
    profile = json.loads(profile_path.read_text())
    paths = profile['queries']
    if len(paths) != profile['query_count'] or len(set(paths)) != len(paths):
        raise ValueError('Current query profile has inconsistent or duplicated entries')
    files: dict[str, bytes] = {}
    suite = []
    for relative in paths:
        path = (root / relative).resolve()
        if not path.is_relative_to(root / 'config/plan7/ql-models') or not path.is_file():
            raise ValueError(f'Invalid current query path: {relative}')
        dest = 'queries/' + path.parent.name + '/' + path.name
        files[dest] = path.read_bytes()
        for helper in path.parent.glob('*.qll'):
            files['queries/' + path.parent.name + '/' + helper.name] = helper.read_bytes()
        suite.append({'query': dest})
    manifest = {'profile': profile['profile'], 'query_count': len(paths),
                'profile_sha256': hashlib.sha256(profile_path.read_bytes()).hexdigest(),
                'source_hashes': {name: hashlib.sha256(value).hexdigest() for name, value in files.items()}}
    identity = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
    pack = output / identity
    pack.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        dest = pack / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists() and dest.read_bytes() != content:
            raise ValueError(f'Query snapshot was modified: {dest}')
        dest.write_bytes(content)
    (pack / 'qlpack.yml').write_text(yaml.safe_dump({'name':'aisast/current-python-suspects',
                                                   'version':'0.0.2',
                                                   'dependencies':{'codeql/python-all':profile['python_all_version']}}))
    lock = root / 'config/plan7/ql-models/cwe22-dynamic-filesystem-access-endpoints/codeql-pack.lock.yml'
    (pack / 'codeql-pack.lock.yml').write_bytes(lock.read_bytes())
    (pack / 'current.qls').write_text(yaml.safe_dump(suite, sort_keys=False))
    (pack / 'snapshot.json').write_text(json.dumps(manifest, indent=2)+'\n')
    return pack / 'current.qls', manifest
