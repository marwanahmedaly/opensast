"""Bundle only the assets needed by the current scanner; never research ledgers."""
import json
from pathlib import Path
from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class ScannerAssetsHook(BuildHookInterface):
    def initialize(self, version, build_data):
        if self.target_name != 'wheel':
            return
        root = Path(self.root).resolve()
        profile = root / 'config/plan7/current-queries.json'
        settings = json.loads(profile.read_text())
        queries = settings['queries']
        if len(queries) != settings['query_count'] or len(set(queries)) != len(queries):
            raise ValueError('Invalid scanner query profile')
        files = {profile}
        base = (root / 'config/plan7/ql-models').resolve()
        for relative in queries:
            path = (root / relative).resolve()
            if not path.is_relative_to(base) or not path.is_file():
                raise ValueError(f'Missing or invalid scanner asset: {relative}')
            files.add(path)
            files.update(path.parent.glob('*.qll'))
        files.add(base / 'cwe22-dynamic-filesystem-access-endpoints/codeql-pack.lock.yml')
        files.update(p for p in (root / 'config/codeql-xss-models').rglob('*') if p.is_file())
        for path in sorted(files):
            if not path.is_file():
                raise ValueError(f'Missing scanner asset: {path}')
            build_data.setdefault('force_include', {})[str(path)] = 'aisast/assets/scanner/' + path.relative_to(root).as_posix()
