"""Public orchestration only; private code, configuration and output stay private."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, HTTPRedirectHandler

FILES = (
    'worker/import_feed.py', 'worker/fetch_feed.py', 'worker/prune_snapshots.py',
    'worker/requirements.txt', 'worker/test_import_feed.py', 'worker/test_download.py',
)
ALLOWED_REQUIREMENTS = {'defusedxml==0.7.1'}
SAFE_REASONS = {'http_challenge', 'origin_backend_failure', 'http_error',
                'network_or_incomplete_transfer', 'html_instead_of_xml',
                'invalid_or_excessive_content_length', 'byte_limit',
                'unexpected_http_status', 'unexpected_content_encoding', 'empty_response'}
MAX_FILE_BYTES = 1024 * 1024
MAX_LOG_BYTES = 8 * 1024 * 1024


class PublicError(Exception):
    """Contains an allowlisted public category, never private exception text."""
    def __init__(self, category): self.category = category


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise PublicError('private_fetch_failed')


def required(name):
    value = os.environ.get(name, '').strip()
    if not value: raise PublicError('configuration_missing')
    return value


def root():
    value = required('RUNNER_TEMP')
    path = Path(value) / 'private-job'
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


def api(path, token):
    request = Request('https://api.github.com/' + path, headers={
        'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'XML-JobRunner/1.0',
    })
    try:
        with build_opener(NoRedirects()).open(request, timeout=30) as response:
            raw = response.read(MAX_FILE_BYTES * 2 + 1)
            if len(raw) > MAX_FILE_BYTES * 2: raise PublicError('private_fetch_failed')
            return json.loads(raw)
    except HTTPError as error:
        error.close()
        raise PublicError('private_access_denied' if error.code in (401, 403, 404) else 'private_fetch_failed') from None
    except (URLError, OSError, ValueError):
        raise PublicError('private_fetch_failed') from None


def prepare():
    repository = required('PRIVATE_REPOSITORY')
    revision = required('PRIVATE_WORKER_REF')
    token = required('PRIVATE_READ_TOKEN')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository): raise PublicError('configuration_invalid')
    if not re.fullmatch(r'[0-9a-f]{40}', revision): raise PublicError('configuration_invalid')
    metadata = api('repos/' + repository, token)
    if metadata.get('private') is not True: raise PublicError('configuration_invalid')
    folder = root()
    for filename in FILES:
        data = api('repos/' + repository + '/contents/' + filename + '?ref=' + revision, token)
        if data.get('type') != 'file' or data.get('encoding') != 'base64': raise PublicError('private_fetch_failed')
        if not isinstance(data.get('size'), int) or not 0 < data['size'] <= MAX_FILE_BYTES:
            raise PublicError('private_fetch_failed')
        try: contents = base64.b64decode(''.join(data['content'].split()), validate=True)
        except (ValueError, KeyError): raise PublicError('private_fetch_failed') from None
        digest = hashlib.sha1(b'blob ' + str(len(contents)).encode() + b'\0' + contents).hexdigest()
        if len(contents) != data['size'] or digest != data.get('sha'): raise PublicError('private_fetch_failed')
        output = folder / filename
        output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        output.write_bytes(contents); output.chmod(0o600)
    print(json.dumps({'phase': 'prepare', 'status': 'passed'}))


def child_environment(include_database=False):
    # Only the import subprocess receives write credentials. GitHub read access
    # is never inherited by the dependency installer or private worker code.
    names = {'PATH', 'RUNNER_TEMP', 'LANG', 'LC_ALL', 'SYSTEMROOT', 'SSL_CERT_FILE',
             'SSL_CERT_DIR', 'HTTPS_PROXY', 'HTTP_PROXY', 'ALL_PROXY', 'NO_PROXY', 'RUNNER_TRACKING_ID'}
    environment = {key: value for key, value in os.environ.items() if key in names}
    environment.update(PYTHONDONTWRITEBYTECODE='1', PYTHONUNBUFFERED='1', TMPDIR=str(root()))
    if include_database:
        environment['SUPABASE_URL'] = required('SUPABASE_URL')
        environment['SUPABASE_SECRET_KEY'] = required('SUPABASE_SECRET_KEY')
    return environment


def command(arguments, phase, timeout, environment=None):
    log = root() / (phase + '.log')
    with log.open('wb') as stream:
        log.chmod(0o600)
        process = subprocess.Popen(arguments, cwd=root(), stdout=stream,
            stderr=subprocess.STDOUT, env=environment or child_environment(), start_new_session=True)
        deadline = time.monotonic() + timeout
        try:
            while process.poll() is None:
                if time.monotonic() > deadline or log.stat().st_size > MAX_LOG_BYTES:
                    os.killpg(process.pid, signal.SIGKILL); process.wait()
                    raise PublicError('runtime_limit')
                time.sleep(0.1)
        except BaseException:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL); process.wait()
            raise
    log.chmod(0o600)
    if log.stat().st_size > MAX_LOG_BYTES: raise PublicError('runtime_limit')
    if process.returncode:
        category = 'verification_failed' if phase in ('dependencies', 'tests') else 'worker_failed'
        # Read only bounded local output. Never print it, traceback or command.
        for line in log.read_bytes()[:MAX_LOG_BYTES].splitlines():
            try: event = json.loads(line)
            except (ValueError, UnicodeDecodeError): continue
            if isinstance(event, dict) and event.get('reason') in SAFE_REASONS:
                category = event['reason']
                if category == 'http_challenge': break
        raise PublicError(category)
    print(json.dumps({'phase': phase, 'status': 'passed'}))


def verify():
    requirements = root() / 'worker/requirements.txt'
    lines = {line.strip() for line in requirements.read_text().splitlines() if line.strip() and not line.lstrip().startswith('#')}
    if lines != ALLOWED_REQUIREMENTS: raise PublicError('requirements_not_allowed')
    command([sys.executable, '-m', 'venv', str(root() / 'venv')], 'environment', 60)
    python = root() / 'venv/bin/python'
    command([str(python), '-m', 'pip', 'install', '--disable-pip-version-check', '--no-cache-dir', '-r', str(requirements)], 'dependencies', 240)
    command([str(python), '-m', 'unittest', 'discover', '-s', 'worker', '-p', 'test_*.py'], 'tests', 90)


def run(mode):
    python = root() / 'venv/bin/python'
    if not python.is_file(): raise PublicError('configuration_missing')
    if mode == 'probe':
        url = required('PRIVATE_FEED_URL')
        command([str(python), 'worker/fetch_feed.py', '--url', url,
                 '--output', str(root() / 'current.xml')], 'probe', 900)
    elif mode == 'curl-probe':
        url = required('PRIVATE_FEED_URL')
        target = root() / 'current.xml'
        command([str(python), '-c',
                 'import sys; sys.path.insert(0,"worker"); from import_feed import approved_url; approved_url(sys.argv[1])',
                 url], 'curl_source_check', 15)
        command(['curl', '--fail', '--silent', '--show-error', '--proto', '=https',
                 '--max-time', '90', '--max-filesize', '120000000',
                 '--output', str(target), url], 'curl_transfer', 100)
        command([str(python), 'worker/import_feed.py', '--file', str(target),
                 '--validate-only'], 'curl_validation', 120)
    elif mode == 'import':
        source = required('PRIVATE_SOURCE_ID')
        # The private worker loads the URL from the authoritative DB source;
        # a probe URL is never rebound to a different seller for publication.
        command([str(python), 'worker/import_feed.py', '--source', source], 'import', 1200,
                child_environment(include_database=True))
        command([str(python), 'worker/prune_snapshots.py', '--apply'], 'retention', 120,
                child_environment(include_database=True))
    else: raise PublicError('configuration_invalid')


def main():
    os.umask(0o077)
    def terminate(signum, frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, terminate)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=['prepare', 'verify', 'probe', 'curl-probe', 'import'])
    args = parser.parse_args()
    try:
        if args.phase == 'prepare': prepare()
        elif args.phase == 'verify': verify()
        else: run(args.phase)
    except PublicError as error:
        print(json.dumps({'phase': args.phase, 'status': 'failed', 'category': error.category}))
        return 1
    except Exception:
        print(json.dumps({'phase': args.phase, 'status': 'failed', 'category': 'internal_failure'}))
        return 1
    return 0


if __name__ == '__main__': raise SystemExit(main())
