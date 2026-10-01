import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import runner


class RunnerTests(unittest.TestCase):
    def test_interruption_terminates_real_child_process(self):
        original = runner.subprocess.Popen
        processes = []
        def spawn(*args, **kwargs):
            process = original(*args, **kwargs)
            processes.append(process)
            return process
        with patch('runner.subprocess.Popen', side_effect=spawn), patch('runner.time.sleep', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                runner.command([sys.executable, '-c', 'import time; time.sleep(60)'], 'cancel_test', 90)
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].poll())

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.environment = patch.dict(os.environ, {'RUNNER_TEMP': self.temporary.name}, clear=True)
        self.environment.start(); self.addCleanup(self.environment.stop)

    def fixture(self, content=b'print("private output")\n'):
        return {'type': 'file', 'encoding': 'base64', 'size': len(content),
                'sha': hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest(),
                'content': base64.b64encode(content).decode()}

    def configure(self):
        os.environ.update(PRIVATE_REPOSITORY='private-owner/private-project',
                          PRIVATE_WORKER_REF='a'*40, PRIVATE_READ_TOKEN='read-credential')

    def test_pinned_private_retrieval_has_no_sensitive_stdout(self):
        self.configure()
        def api(path, token):
            self.assertEqual(token, 'read-credential')
            return {'private': True} if path.endswith('/private-project') else self.fixture()
        capture = io.StringIO()
        with patch('runner.api', side_effect=api) as call, contextlib.redirect_stdout(capture): runner.prepare()
        self.assertEqual(call.call_count, 1 + len(runner.FILES))
        self.assertEqual(json.loads(capture.getvalue()), {'phase': 'prepare', 'status': 'passed'})
        self.assertNotIn('private-project', capture.getvalue())
        for path in runner.FILES: self.assertTrue((runner.root()/path).is_file())

    def test_mutable_revision_and_invalid_repository_are_rejected(self):
        self.configure()
        for name, value in [('PRIVATE_WORKER_REF', 'main'), ('PRIVATE_REPOSITORY', '../../bad')]:
            with patch.dict(os.environ, {name: value}), patch('runner.api') as api:
                with self.assertRaises(runner.PublicError): runner.prepare()
                api.assert_not_called()

    def test_public_source_repo_is_rejected(self):
        self.configure()
        with patch('runner.api', return_value={'private': False}):
            with self.assertRaises(runner.PublicError): runner.prepare()

    def test_content_hash_mismatch_is_rejected(self):
        self.configure(); bad = self.fixture(); bad['sha'] = '0'*40
        with patch('runner.api', side_effect=[{'private': True}, bad]):
            with self.assertRaises(runner.PublicError): runner.prepare()

    def test_read_and_database_secrets_are_absent_from_probe_environment(self):
        self.configure()
        os.environ.update(SUPABASE_URL='https://private.example', SUPABASE_SECRET_KEY='db-secret', OTHER_SECRET='unrelated')
        environment = runner.child_environment()
        for name in ['PRIVATE_READ_TOKEN','PRIVATE_REPOSITORY','SUPABASE_SECRET_KEY','SUPABASE_URL','OTHER_SECRET']:
            self.assertNotIn(name, environment)
        imported = runner.child_environment(include_database=True)
        self.assertEqual(imported['SUPABASE_SECRET_KEY'], 'db-secret')
        self.assertNotIn('PRIVATE_READ_TOKEN', imported)

    def test_private_exception_and_worker_output_are_not_public(self):
        capture = io.StringIO()
        private_text = 'SECRET https://private.example/feed.xml private-project'
        code = 'print(' + repr(private_text) + '); raise RuntimeError(' + repr(private_text) + ')'
        with contextlib.redirect_stdout(capture):
            with self.assertRaises(runner.PublicError) as error:
                runner.command([sys.executable, '-c', code], 'probe', 5)
        self.assertEqual(error.exception.category, 'worker_failed')
        self.assertNotIn('SECRET', capture.getvalue()); self.assertNotIn('private.example', capture.getvalue())

    def test_challenge_category_is_preserved_without_endpoint(self):
        code = 'print(' + repr(json.dumps({'reason':'http_challenge','host':'private.example'})) + '); exit(1)'
        with self.assertRaises(runner.PublicError) as error:
            runner.command([sys.executable, '-c', code], 'probe', 5)
        self.assertEqual(error.exception.category, 'http_challenge')

    def test_runtime_timeout_stops_child(self):
        with self.assertRaises(runner.PublicError) as error:
            runner.command([sys.executable, '-c', 'import time; time.sleep(10)'], 'probe', 0.05)
        self.assertEqual(error.exception.category, 'runtime_limit')

    def test_fast_excessive_output_is_rejected(self):
        with patch('runner.MAX_LOG_BYTES', 256):
            with self.assertRaises(runner.PublicError) as error:
                runner.command([sys.executable, '-c', 'print("x"*4096)'], 'probe', 5)
        self.assertEqual(error.exception.category, 'runtime_limit')

    def test_unreviewed_dependency_is_rejected(self):
        requirements = runner.root()/'worker/requirements.txt'
        requirements.parent.mkdir(); requirements.write_text('https://private.example/package.whl\n')
        with patch('runner.command') as command:
            with self.assertRaises(runner.PublicError): runner.verify()
            command.assert_not_called()

    def test_probe_never_passes_database_credentials(self):
        python = runner.root()/'venv/bin/python'; python.parent.mkdir(parents=True); python.touch()
        os.environ.update(PRIVATE_FEED_URL='https://private.example/feed.xml',SUPABASE_SECRET_KEY='db-secret')
        with patch('runner.command') as command:
            runner.run('probe')
        self.assertEqual(command.call_count, 1)
        arguments = command.call_args.args[0]
        self.assertIn('worker/fetch_feed.py', arguments)
        self.assertNotIn('db-secret', str(command.call_args))

    def test_import_uses_authoritative_source_and_only_then_retention(self):
        python = runner.root()/'venv/bin/python'; python.parent.mkdir(parents=True); python.touch()
        os.environ.update(PRIVATE_SOURCE_ID='private-source',SUPABASE_URL='https://private.example',SUPABASE_SECRET_KEY='db-secret')
        with patch('runner.command') as command: runner.run('import')
        self.assertEqual(command.call_count, 2)
        self.assertIn('worker/import_feed.py', command.call_args_list[0].args[0])
        self.assertNotIn('--file', command.call_args_list[0].args[0])
        self.assertIn('worker/prune_snapshots.py', command.call_args_list[1].args[0])
        with patch('runner.command', side_effect=runner.PublicError('worker_failed')) as command:
            with self.assertRaises(runner.PublicError): runner.run('import')
            self.assertEqual(command.call_count, 1)

    def test_redirect_never_forwards_private_authorization(self):
        redirect = runner.NoRedirects()
        with self.assertRaises(runner.PublicError): redirect.redirect_request(None,None,302,'redirect',{},'https://other.example')


if __name__ == '__main__': unittest.main()
