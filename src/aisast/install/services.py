"""Small user-local process controller. Only recorded, identity-matching processes stop."""
import fcntl
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import httpx

from aisast.product.incremental import atomic_json
from aisast.product.store import private_directory, state_home


def records():
    return private_directory(state_home() / 'services')


def marker(pid):
    try:
        text = Path(f'/proc/{pid}/stat').read_text()
        fields = text.rsplit(') ', 1)[1].split()
        return None if fields[0] == 'Z' else fields[19]
    except (OSError, IndexError):
        return None


def alive(record):
    return bool(record.get('start_ticks')) and marker(record['pid']) == record['start_ticks']


def load(path):
    return json.loads(path.read_text()) if path.is_file() else {}


def launch(name, command, cwd=None, extra_env=None):
    folder = records()
    path = folder / (name + '.json')
    with (folder / 'control.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        previous = load(path)
        if alive(previous):
            print(f'{name} already running (PID {previous["pid"]}).')
            return previous
        environment = {**os.environ, 'OPENSAST_HOME': str(state_home().resolve()), **(extra_env or {})}
        with (folder / (name + '.log')).open('ab') as output:
            process = subprocess.Popen(command, cwd=cwd, env=environment, stdout=output, stderr=output,
                                       stdin=subprocess.DEVNULL, start_new_session=True)
        record = {'pid': process.pid, 'start_ticks': marker(process.pid), 'command': command,
                  'cwd': str(cwd) if cwd else None, 'started_at': time.time()}
        atomic_json(path, record)
        time.sleep(.3)
        if process.poll() is not None:
            raise RuntimeError(f'{name} failed to start. Inspect {folder / (name + ".log")}')
        print(f'{name} started (PID {process.pid}). Log: {folder / (name + ".log")}')
        return record


def wait_ready(name, url, seconds):
    deadline = time.monotonic() + seconds
    with httpx.Client(timeout=3, trust_env=False) as client:
        while time.monotonic() < deadline:
            if not alive(load(records() / (name + '.json'))):
                raise RuntimeError(f'{name} stopped. Inspect {records() / (name + ".log")}')
            try:
                if client.get(url).status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(1)
    raise RuntimeError(f'{name} is still starting or unavailable; inspect its log and run opensast doctor.')


def start_worker(root, config, settings):
    root = Path(root).resolve()
    name = 'worker-' + config['project_id']
    # Credentials and engine settings stay private; no tokens enter the process command.
    launch(name, [sys.executable, '-m', 'aisast.product.cli', 'worker'], cwd=root)


def start(settings, workers=True):
    local = settings.get('local_model')
    if local:
        environment = {'LD_LIBRARY_PATH': os.pathsep.join(local['library_paths'] +
                       ([os.environ['LD_LIBRARY_PATH']] if os.environ.get('LD_LIBRARY_PATH') else []))}
        command = [local['server'], '-m', local['weights'], '--host', '127.0.0.1', '--port', str(local['port']),
                   '--ctx-size', str(settings['context_window']), '--parallel', '1', '--alias', settings['model'], '--jinja', '--reasoning', 'off',
                   '--no-cache-prompt', '--gpu-layers', str(local['gpu_layers'])]
        if local['gpu_layers']:
            command.extend(['--split-mode', 'layer', '--flash-attn', 'on'])
        launch('model', command, extra_env=environment)
        wait_ready('model', f'http://127.0.0.1:{local["port"]}/health', 300)
    dashboard = settings.get('dashboard', {'host': '127.0.0.1', 'port': 8765})
    launch('dashboard', [sys.executable, '-m', 'aisast.product.cli', 'serve', '--host', dashboard['host'],
                         '--port', str(dashboard['port'])])
    wait_ready('dashboard', f'http://127.0.0.1:{dashboard["port"]}/api/health', 30)
    if workers:
        for path in records().glob('worker-*.json'):
            record = load(path)
            root = Path(record['cwd']) if record.get('cwd') else None
            if root and (root / '.opensast/config.json').is_file():
                start_worker(root, load(root / '.opensast/config.json'), settings)
    print(f'Dashboard: http://127.0.0.1:{dashboard["port"]}')


def stop():
    for path in sorted(records().glob('*.json'), key=lambda p: (not p.name.startswith('worker-'), p.name)):
        record = load(path)
        if not alive(record):
            continue
        print('Stopping ' + path.stem)
        try:
            os.killpg(record['pid'], signal.SIGINT)
        except ProcessLookupError:
            continue
        deadline = time.monotonic() + 20
        while alive(record) and time.monotonic() < deadline:
            time.sleep(.2)
        if alive(record):
            try:
                os.killpg(record['pid'], signal.SIGTERM)
            except ProcessLookupError:
                continue
            time.sleep(1)
        if alive(record):
            try:
                os.killpg(record['pid'], signal.SIGKILL)
            except ProcessLookupError:
                pass
    print('Managed processes stopped. Accounts, projects, scan history and models are preserved.')
