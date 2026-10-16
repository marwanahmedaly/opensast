"""Interactive local-first provisioning, saved engine defaults and readiness checks."""
import argparse
import getpass
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import yaml

from aisast.product.client import validate_url
from aisast.product.incremental import atomic_json
from aisast.product.store import Store, private_directory, state_home
from aisast.resources import scanner_root
from .downloads import download, extract, sha256

MANIFEST = json.loads(Path(__file__).with_name('manifest.json').read_text())
DEFAULTS = {'codeql': 'codeql', 'query_search_path': None, 'endpoint': None, 'model': None,
            'model_revision': None, 'allow_model_host': [], 'context_window': 16384, 'max_tokens': 400}


def audit(event, **values):
    from datetime import datetime, timezone
    path = private_directory(state_home() / 'logs') / 'installation.jsonl'
    with path.open('a') as stream:
        stream.write(json.dumps({'at': datetime.now(timezone.utc).isoformat(), 'event': event, **values}) + '\n')
    path.chmod(0o600)


def settings_path():
    return private_directory(state_home()) / 'installation.json'


def load_settings():
    path = settings_path()
    return json.loads(path.read_text()) if path.is_file() else {}


def apply_engine_defaults(args):
    saved = load_settings()
    for key, default in DEFAULTS.items():
        if getattr(args, key, None) is None:
            setattr(args, key, saved.get(key, default))
    if args.query_search_path:
        args.query_search_path = Path(args.query_search_path)
    if getattr(args, 'suspect_only', False):
        args.endpoint = args.model = args.model_revision = None


def prompt(message, default=None, noninteractive=False):
    if noninteractive:
        if default is None:
            raise RuntimeError(f'Unattended setup needs an explicit value: {message}')
        return default
    suffix = f' [{default}]' if default is not None else ''
    answer = input(message + suffix + ': ').strip()
    return answer or default


def confirm(message, args):
    if args.yes:
        return
    if args.non_interactive or prompt(message + ' (yes/no)', 'yes').lower() not in {'yes', 'y'}:
        raise RuntimeError('Setup cancelled before downloading. Use --yes for unattended provisioning.')


def command(args, logfile):
    with Path(logfile).open('a') as log:
        result = subprocess.run(args, stdout=log, stderr=log, check=False)
    if result.returncode:
        raise RuntimeError(f'Command failed. Inspect {logfile}')


def executable_version(executable):
    value = shutil.which(str(executable))
    if not value:
        raise RuntimeError(f'Executable not found: {executable}')
    result = subprocess.run([value, 'version', '--format=json'], text=True, capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError('CodeQL version check failed: ' + result.stderr.strip())
    return value, json.loads(result.stdout)['version']


def required_packs():
    lock = scanner_root() / 'config/plan7/ql-models/cwe22-dynamic-filesystem-access-endpoints/codeql-pack.lock.yml'
    versions = {name: metadata['version'] for name, metadata in yaml.safe_load(lock.read_text())['dependencies'].items()}
    versions['codeql/python-queries'] = MANIFEST['python_queries_version']
    return versions


def missing_packs(root):
    found = set()
    if root and Path(root).is_dir():
        for path in Path(root).rglob('qlpack.yml'):
            metadata = yaml.safe_load(path.read_text()) or {}
            found.add((metadata.get('name'), str(metadata.get('version'))))
    return [f'{name}@{version}' for name, version in required_packs().items() if (name, version) not in found]


def provision_codeql(args):
    home = private_directory(state_home() / 'tools')
    cache = private_directory(state_home() / 'downloads')
    logs = private_directory(state_home() / 'logs')
    binary = args.codeql
    if not binary:
        bundle = home / ('codeql-' + MANIFEST['codeql_version'])
        candidates = [p for p in bundle.rglob('codeql') if p.is_file() and os.access(p, os.X_OK)] if bundle.exists() else []
        if not candidates:
            print('CodeQL use is governed by GitHub’s terms: ' + MANIFEST['codeql_terms'])
            if not args.offline:
                confirm('Install the pinned CodeQL Python bundle (about 111 MB)?', args)
            if shutil.disk_usage(home).free < 2 * 1024**3:
                raise RuntimeError('CodeQL provisioning needs at least 2 GiB free for download, extraction and packs.')
            archive = download(MANIFEST['codeql'], cache, args.offline)
            extract(archive, bundle)
            candidates = [p for p in bundle.rglob('codeql') if p.is_file() and os.access(p, os.X_OK)]
        if len(candidates) != 1:
            raise RuntimeError('Cannot locate the CodeQL executable in the installed bundle.')
        binary = str(candidates[0])
    binary, version = executable_version(binary)
    if version != MANIFEST['codeql_version']:
        raise RuntimeError(f'This installer pins CodeQL {MANIFEST["codeql_version"]}; supplied binary is {version}. Omit --codeql to provision the pinned version.')
    packs = Path(args.query_search_path).expanduser().resolve() if args.query_search_path else home / 'packs'
    packs.mkdir(parents=True, exist_ok=True)
    absent = missing_packs(packs)
    if absent:
        if args.offline:
            raise RuntimeError('Offline packs missing: ' + ', '.join(absent))
        confirm('Download the matching pinned CodeQL Python packs?', args)
        command([binary, 'pack', 'download', '--dir=' + str(packs), *absent], logs / 'codeql-install.log')
        absent = missing_packs(packs)
        if absent:
            raise RuntimeError('Pack installation incomplete: ' + ', '.join(absent))
    return {'codeql': binary, 'query_search_path': str(packs)}


def hardware():
    result = {'platform': platform.platform(), 'architecture': platform.machine(),
              'python': platform.python_version(), 'free_disk_gib': round(shutil.disk_usage(state_home()).free / 1024**3, 1),
              'ram_gib': 0, 'gpu_memory_mib': []}
    try:
        memory = next(line for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemTotal:'))
        result['ram_gib'] = round(int(memory.split()[1]) / 1024**2, 1)
    except (OSError, StopIteration, ValueError):
        pass
    if shutil.which('nvidia-smi'):
        try:
            response = subprocess.run(['nvidia-smi', '--query-gpu=memory.total', '--format=csv,noheader,nounits'],
                                      text=True, capture_output=True, timeout=10)
            if not response.returncode:
                result['gpu_memory_mib'] = [int(line.strip()) for line in response.stdout.splitlines()]
        except (OSError, ValueError, subprocess.TimeoutExpired):
            pass
    return result


def provision_model(args, info):
    if args.endpoint:
        mode = 'endpoint'
    elif args.gguf:
        mode = 'gguf'
    else:
        mode = args.model_mode
    if not mode:
        print('\nModel setup:\n  1. Download the pinned local Qwen model (17.4 GB)\n  2. Use a GGUF already on this machine\n  3. Connect an existing internal llama.cpp endpoint')
        choice = prompt('Choose model setup', '1', args.non_interactive)
        mode = {'1': 'download', '2': 'gguf', '3': 'endpoint'}.get(choice)
    if mode not in {'download', 'gguf', 'endpoint'}:
        raise RuntimeError('Choose download, gguf or endpoint for --model-mode.')
    if mode == 'endpoint':
        endpoint = args.endpoint or prompt('Internal inference URL', None, args.non_interactive)
        if not endpoint:
            raise RuntimeError('An internal inference URL is required.')
        hostname = urlsplit(endpoint).hostname
        allowed = args.allow_model_host or []
        if hostname not in {'localhost', '127.0.0.1', '::1'} and hostname not in allowed:
            if args.non_interactive:
                raise RuntimeError('Pass --allow-model-host for the company-internal inference hostname.')
            print('Inference must stay inside your infrastructure. This endpoint must support llama.cpp template/tokenizer APIs.')
            answer = prompt(f'Confirm {hostname} is your internal inference host (yes/no)', 'no')
            if answer.lower() not in {'yes', 'y'}:
                raise RuntimeError('Internal endpoint was not confirmed.')
            allowed = [*allowed, hostname]
        endpoint = validate_url(endpoint, allowed)
        name = args.model or prompt('Model name served by this endpoint', None, args.non_interactive)
        if not name:
            raise RuntimeError('A served model name is required.')
        revision = args.model_revision
        if revision is None:
            revision = prompt('Immutable model revision or weight SHA-256 (empty disables result reuse)', '', args.non_interactive)
        return {'endpoint': endpoint, 'model': name, 'model_revision': revision or None, 'allow_model_host': allowed}
    if mode == 'download':
        if info['ram_gib'] < 24 and sum(info['gpu_memory_mib']) < 24 * 1024:
            raise RuntimeError('The default 30B model needs substantial memory. This host has less than 24 GiB RAM and aggregate GPU memory. Use an internal endpoint or supply a suitable local GGUF.')
        confirm('Download the local Qwen GGUF (17.4 GB; hash matches the recorded research weights)?', args)
        weights = download(MANIFEST['model'], private_directory(state_home() / 'models'), args.offline)
        name = MANIFEST['model']['model_id']
        revision = MANIFEST['model']['sha256']
    else:
        value = args.gguf or prompt('Absolute path to your GGUF', None, args.non_interactive)
        if not value:
            raise RuntimeError('A GGUF path is required.')
        weights = Path(value).expanduser().resolve()
        if not weights.is_file():
            raise RuntimeError('GGUF file not found: ' + str(weights))
        with weights.open('rb') as stream:
            if stream.read(4) != b'GGUF':
                raise RuntimeError('The supplied file does not have a GGUF header.')
        print('Hashing local model weights for cache identity…', flush=True)
        revision = sha256(weights)
        name = args.model or weights.stem
    backend = args.backend or ('cuda' if info['gpu_memory_mib'] else 'cpu')
    local = private_directory(state_home() / 'tools')
    directories = []
    if args.llama_server:
        server = Path(args.llama_server).expanduser().resolve()
        if not server.is_file() or not os.access(server, os.X_OK):
            raise RuntimeError('llama-server executable not found: ' + str(server))
        directories = [str(server.parent)]
    else:
        spec = MANIFEST['llama_' + backend]
        destination = local / ('llama-' + MANIFEST['llama_version'] + '-' + backend)
        if not destination.exists():
            confirm(f'Install pinned llama.cpp {MANIFEST["llama_version"]} ({backend})?', args)
            extract(download(spec, private_directory(state_home() / 'downloads'), args.offline), destination)
        servers = list(destination.rglob('llama-server'))
        if len(servers) != 1:
            raise RuntimeError('Cannot locate llama-server in the installed runtime.')
        server = servers[0]
        directories = [str(server.parent)]
        directories += sorted({str(p.parent) for p in destination.rglob('*.so*')})
        if backend == 'cuda':
            runtime = local / ('llama-cudart-' + MANIFEST['llama_version'])
            if not runtime.exists():
                extract(download(MANIFEST['llama_cuda_runtime'], private_directory(state_home() / 'downloads'), args.offline), runtime)
            directories += sorted({str(p.parent) for p in runtime.rglob('*.so*')})
    return {'endpoint': f'http://127.0.0.1:{args.model_port}/v1', 'model': name, 'model_revision': revision,
            'allow_model_host': [], 'local_model': {'server': str(server), 'weights': str(weights), 'port': args.model_port,
            'gpu_layers': 99 if backend == 'cuda' else 0, 'library_paths': list(dict.fromkeys(directories)), 'backend': backend}}


def probe_model(settings):
    endpoint = validate_url(settings['endpoint'], settings.get('allow_model_host', []))
    base = endpoint.removesuffix('/v1')
    with httpx.Client(timeout=15, trust_env=False) as client:
        response = client.get(endpoint + '/models')
        response.raise_for_status()
        names = {model['id'] for model in response.json()['data']}
        local = settings.get('local_model')
        if settings['model'] not in names:
            if local and len(names) == 1:
                settings['model'] = next(iter(names))
            else:
                raise RuntimeError('Configured model name is not in the endpoint’s /v1/models response.')
        response = client.post(base + '/apply-template', json={'messages': [{'role': 'user', 'content': 'OpenSAST readiness check.'}],
                                                              'add_generation_prompt': True, 'jinja': True})
        response.raise_for_status()
        text = response.json()['prompt']
        response = client.post(base + '/tokenize', json={'content': text, 'add_special': True})
        response.raise_for_status()
        if not isinstance(response.json()['tokens'], list):
            raise RuntimeError('Tokenizer endpoint did not return tokens.')


def bootstrap(args, settings):
    store = Store(state_home() / 'server')
    with store.connect() as db:
        exists = db.execute('SELECT 1 FROM users LIMIT 1').fetchone()
    if exists:
        print('Existing accounts, workspaces and project history preserved.')
        return
    username = args.username or prompt('Administrator username', 'admin', args.non_interactive)
    workspace = args.workspace or prompt('Team/workspace name', 'Personal', args.non_interactive)
    if args.password_file:
        password = args.password_file.expanduser().read_text().rstrip('\r\n')
    elif args.non_interactive:
        raise RuntimeError('First unattended setup needs --password-file pointing to a private file.')
    else:
        password = getpass.getpass('Administrator password (at least 12 characters): ')
        if password != getpass.getpass('Repeat password: '):
            raise RuntimeError('Passwords do not match.')
    store.bootstrap(username, password, workspace)
    session = store.login(username, password)
    url = f'http://127.0.0.1:{settings["dashboard"]["port"]}'
    atomic_json(private_directory(state_home() / 'client') / 'credentials.json', {'server': url, 'token': session['token']})
    print('Administrator created. CLI login saved privately.')


def configure(args):
    if sys.platform != 'linux' or platform.machine() not in {'x86_64', 'amd64'}:
        raise RuntimeError('Automatic provisioning currently supports Linux x86-64. Use the documented source/manual setup on other platforms.')
    if args.context_window <= args.max_tokens + 64 or args.max_tokens < 1:
        raise RuntimeError('Invalid context/completion token budget.')
    if any(not 1024 <= value <= 65535 for value in (args.model_port, args.dashboard_port)):
        raise RuntimeError('Choose unprivileged ports between 1024 and 65535.')
    if args.model_port == args.dashboard_port:
        raise RuntimeError('Model and dashboard need different ports.')
    if args.non_interactive and not args.password_file:
        initial = Store(state_home() / 'server')
        with initial.connect() as db:
            if not db.execute('SELECT 1 FROM users LIMIT 1').fetchone():
                raise RuntimeError('First unattended setup needs --password-file before any downloads.')
    audit('setup_started', offline=args.offline)
    info = hardware()
    print(f'Host: Python {info["python"]}, RAM {info["ram_gib"]} GiB, free disk {info["free_disk_gib"]} GiB; NVIDIA GPU memory: {info["gpu_memory_mib"]} MiB')
    settings = load_settings()
    supplied = any(getattr(args, key, None) for key in ('codeql','query_search_path','endpoint','model_mode','gguf','llama_server','model','model_revision','backend'))
    if not settings or args.reconfigure or supplied:
        engines = provision_codeql(args)
        audit('codeql_configured', version=MANIFEST['codeql_version'])
        model = provision_model(args, info)
        audit('model_configured', mode='local' if model.get('local_model') else 'internal_endpoint', revision=model.get('model_revision'))
        settings = {**engines, **model, 'version': 1,
                    'context_window': args.context_window, 'max_tokens': args.max_tokens,
                    'dashboard': {'host': '127.0.0.1', 'port': args.dashboard_port}}
        if settings['context_window'] <= settings['max_tokens'] + 64 or settings['max_tokens'] < 1:
            raise RuntimeError('Invalid context/completion token budget.')
        for value in (args.model_port, args.dashboard_port):
            if not 1024 <= value <= 65535:
                raise RuntimeError('Choose an unprivileged port between 1024 and 65535.')
        atomic_json(settings_path(), settings)
    else:
        print('Reusing saved setup. Use opensast setup --reconfigure to change it.')
    bootstrap(args, settings)
    if not args.no_start:
        from .services import start
        if not settings.get('local_model'):
            probe_model(settings)
        start(settings)
        probe_model(settings)
        atomic_json(settings_path(), settings)
        print('\nReady. From a Python project directory:\n  opensast init\n  opensast scan\n\nopensast init provisions a project worker using these saved settings.')
    else:
        print('Setup saved. Run opensast start, then opensast doctor before scanning.')
    audit('setup_completed', started=not args.no_start)
    return 0


def doctor():
    findings = []
    settings = load_settings()
    if not settings:
        print('NOT READY: run opensast setup.')
        return 1
    try:
        profile = json.loads((scanner_root() / 'config/plan7/current-queries.json').read_text())
        files = profile['queries']
        if len(files) != profile['query_count'] or len(set(files)) != len(files) or not all((scanner_root() / p).is_file() for p in files):
            raise RuntimeError('Incomplete scanner query assets.')
        print(f'OK: packaged scanner profile ({profile["query_count"]} queries).')
        _, version = executable_version(settings['codeql'])
        if version != MANIFEST['codeql_version']:
            raise RuntimeError('CodeQL version differs from the installed profile.')
        absent = missing_packs(settings['query_search_path'])
        if absent:
            raise RuntimeError('Missing pinned packs: ' + ', '.join(absent))
        print('OK: CodeQL and matching Python packs.')
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
        findings.append(str(exc))
    try:
        probe_model(settings)
        print('OK: configured local/internal model, template and tokenizer endpoints.')
    except (httpx.HTTPError, OSError, RuntimeError, ValueError, KeyError) as exc:
        findings.append('Inference: ' + str(exc))
    try:
        port = settings['dashboard']['port']
        with httpx.Client(timeout=5, trust_env=False) as client:
            client.get(f'http://127.0.0.1:{port}/api/health').raise_for_status()
        print('OK: dashboard/API available.')
    except (httpx.HTTPError, KeyError) as exc:
        findings.append('Dashboard: ' + str(exc))
    for issue in findings:
        print('NOT READY: ' + issue)
    print('Readiness checks do not establish detection accuracy. Logs: ' + str(state_home() / 'logs'))
    return 1 if findings else 0


def parser(commands):
    p = commands.add_parser('setup', help='Guided local installation of CodeQL, model and dashboard')
    p.add_argument('--offline', action='store_true'); p.add_argument('--yes', action='store_true')
    p.add_argument('--non-interactive', action='store_true'); p.add_argument('--reconfigure', action='store_true')
    p.add_argument('--no-start', action='store_true'); p.add_argument('--codeql'); p.add_argument('--query-search-path')
    p.add_argument('--model-mode', choices=['download','gguf','endpoint']); p.add_argument('--gguf')
    p.add_argument('--llama-server'); p.add_argument('--backend', choices=['cpu','cuda'])
    p.add_argument('--endpoint'); p.add_argument('--model'); p.add_argument('--model-revision')
    p.add_argument('--allow-model-host', action='append', default=[])
    p.add_argument('--username'); p.add_argument('--workspace'); p.add_argument('--password-file', type=Path)
    p.add_argument('--dashboard-port', type=int, default=8765); p.add_argument('--model-port', type=int, default=8000)
    p.add_argument('--context-window', type=int, default=16384); p.add_argument('--max-tokens', type=int, default=400)
    commands.add_parser('doctor', help='Check packaged assets, local engines and service readiness')
    commands.add_parser('start', help='Start the configured model/dashboard and remembered workers')
    commands.add_parser('stop', help='Stop only OpenSAST-managed processes; preserve all data')
    commands.add_parser('restart', help='Restart managed services with current code/configuration')
