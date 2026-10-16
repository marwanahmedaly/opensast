"""Resumable, checksum-verified setup downloads and filtered archive extraction."""
import hashlib
import os
import shutil
import tarfile
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def download(spec, directory, offline=False):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination = directory / spec['filename']
    if destination.is_file():
        if sha256(destination) == spec['sha256']:
            return destination
        raise RuntimeError(f'Checksum mismatch in {destination}. Move this file aside before retrying.')
    if offline:
        raise RuntimeError(f'Offline asset missing: {destination}; expected SHA-256 {spec["sha256"]}')
    url = spec['url']
    mirror = os.environ.get('OPENSAST_DOWNLOAD_MIRROR')
    if mirror:
        url = mirror.rstrip('/') + '/' + spec['filename']
    if urlsplit(url).scheme != 'https' or urlsplit(url).username or urlsplit(url).password:
        raise ValueError('Setup downloads require HTTPS')
    temporary = destination.with_name(destination.name + '.part')
    offset = temporary.stat().st_size if temporary.is_file() else 0
    needed = max(0, spec['bytes'] - offset) + 64 * 1024 * 1024
    if shutil.disk_usage(directory).free < needed:
        raise RuntimeError(f'Insufficient disk space for {spec["filename"]}; need {needed / 1024**3:.1f} GiB free.')
    print(f'Downloading {spec["filename"]} ({spec["bytes"] / 1024**3:.2f} GiB). Interrupted downloads can resume.', flush=True)
    if offset < spec['bytes']:
        headers = {'Range': f'bytes={offset}-'} if offset else {}
        with httpx.Client(timeout=httpx.Timeout(60, connect=20), follow_redirects=True) as client:
            with client.stream('GET', url, headers=headers) as response:
                response.raise_for_status()
                if urlsplit(str(response.url)).scheme != 'https':
                    raise RuntimeError('Download redirected to an insecure URL')
                resumed = offset > 0 and response.status_code == 206
                if resumed and not response.headers.get('content-range', '').startswith(f'bytes {offset}-'):
                    raise RuntimeError('Download server returned an invalid resume range')
                if not resumed:
                    offset = 0
                last = time.monotonic()
                with temporary.open('ab' if resumed else 'wb') as stream:
                    os.chmod(temporary, 0o600)
                    for chunk in response.iter_bytes(4 * 1024 * 1024):
                        offset += len(chunk)
                        if offset > spec['bytes']:
                            raise RuntimeError('Download exceeded its pinned expected size')
                        stream.write(chunk)
                        if time.monotonic() - last > 10:
                            print(f'  {100 * offset / spec["bytes"]:.0f}% downloaded', flush=True)
                            last = time.monotonic()
                    stream.flush()
                    os.fsync(stream.fileno())
    if not temporary.is_file() or temporary.stat().st_size != spec['bytes'] or sha256(temporary) != spec['sha256']:
        temporary.unlink(missing_ok=True)
        raise RuntimeError('Downloaded asset failed size/SHA-256 verification; it was not installed.')
    temporary.replace(destination)
    return destination


def extract(archive, destination):
    """Install archives into a fresh directory; reject unsafe members before extraction."""
    destination = Path(destination)
    if destination.exists():
        return destination
    if not hasattr(tarfile, 'data_filter'):
        raise RuntimeError('Archive installation requires Python 3.11.8+ or 3.12+ with tarfile data filtering.')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.extract-', dir=destination.parent) as name:
        stage = Path(name) / 'payload'
        stage.mkdir()
        if str(archive).endswith('.zst'):
            try:
                import zstandard
            except ImportError as exc:
                raise RuntimeError('Install the setup extra: evidence-grounded-aisast[web,install]') from exc
            with Path(archive).open('rb') as source, zstandard.ZstdDecompressor().stream_reader(source) as reader:
                with tarfile.open(fileobj=reader, mode='r|') as bundle:
                    for member in bundle:
                        bundle.extract(member, stage, filter='data')
        else:
            with tarfile.open(archive, 'r:*') as bundle:
                bundle.extractall(stage, filter='data')
        stage.replace(destination)
    return destination
