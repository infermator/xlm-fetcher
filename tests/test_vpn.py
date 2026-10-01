import base64
import sys
from pathlib import Path
import unittest
import contextlib
import io
import json
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vpn import configuration, health, probe
from runner import PublicError

KEY = base64.b64encode(b'x' * 32).decode()
CONFIG = f'''[Interface]
PrivateKey = {KEY}
Address = 10.20.0.2/32
DNS = 1.1.1.1
MTU = 1300
[Peer]
PublicKey = {KEY}
PresharedKey = {KEY}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example.org:51820
PersistentKeepalive = 15
'''


def resolver(*args):
    return [(2, 1, 6, '', ('8.8.8.8', 443))]


class VPNTests(unittest.TestCase):
    def test_routes_only_feed_and_does_not_apply_dns(self):
        result, host, ips = configuration(CONFIG, 'https://feed.example.org/export.xml', resolver)
        self.assertIn('AllowedIPs = 8.8.8.8/32', result)
        self.assertNotIn('0.0.0.0/0', result)
        self.assertNotIn('::/0', result)
        self.assertNotIn('DNS', result)
        self.assertEqual((host, ips), ('feed.example.org', ['8.8.8.8']))

    def test_arbitrary_hooks_rejected(self):
        with self.assertRaises(PublicError):
            configuration(CONFIG.replace('MTU = 1300', 'PostUp = echo unsafe'), 'https://feed.example.org/x', resolver)

    def test_nonpublic_destinations_rejected(self):
        with self.assertRaises(PublicError):
            configuration(CONFIG, 'https://feed.example.org/x', lambda *a: [(2, 1, 6, '', ('127.0.0.1', 443))])

    def test_credential_url_and_invalid_key_rejected(self):
        with self.assertRaises(PublicError):
            configuration(CONFIG, 'https://user:secret@feed.example.org/x', resolver)
        with self.assertRaises(PublicError):
            configuration(CONFIG.replace(KEY, 'bad'), 'https://feed.example.org/x', resolver)

    def test_diagnostics_do_not_include_private_config(self):
        try:
            configuration(CONFIG + 'PostUp = private-value\n', 'https://feed.example.org/x', resolver)
        except PublicError as error:
            self.assertEqual(error.category, 'vpn_configuration_invalid')
            self.assertNotIn(KEY, str(error))

    def test_health_prints_only_booleans_without_peer_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / 'vpn_handshake_check.log').write_text(KEY + '\t12345\n')
            (folder / 'vpn_transfer_check.log').write_text(KEY + '\t456\t789\n')
            output = io.StringIO()
            with patch('vpn.root', return_value=folder), patch('vpn.command'), contextlib.redirect_stdout(output):
                health()
            data = json.loads(output.getvalue())
            self.assertEqual(data, {'phase': 'vpn_health', 'handshake': True, 'received_data': True, 'sent_data': True})
            self.assertNotIn(KEY, output.getvalue())

    def test_failed_connectivity_keeps_health_diagnostics_and_stops(self):
        with patch('vpn.required', return_value='https://feed.example.org/x'), patch('vpn.socket.create_connection', side_effect=TimeoutError()), patch('vpn.health') as check:
            with self.assertRaises(PublicError) as raised:
                probe()
            self.assertEqual(raised.exception.category, 'vpn_feed_unreachable')
            check.assert_called_once()
