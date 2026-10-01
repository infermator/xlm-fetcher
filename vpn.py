"""Optional operator-authorized WireGuard access, scoped to one feed host."""
import argparse
import base64
import configparser
import ipaddress
import http.client
import json
import os
from pathlib import Path
import re
import socket
import ssl
from urllib.parse import urlsplit

from runner import PublicError, command, required, root

MARKER = ' # xml-worker-vpn'
INTERFACE = 'xmlfeed'


def configuration(raw, url, resolver=socket.getaddrinfo):
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    try:
        parser.read_string(raw)
        if set(parser.sections()) != {'Interface', 'Peer'}:
            raise ValueError()
        interface, peer = parser['Interface'], parser['Peer']
        if set(interface) - {'PrivateKey', 'Address', 'DNS', 'MTU'}:
            raise ValueError()
        if set(peer) - {'PublicKey', 'PresharedKey', 'AllowedIPs', 'Endpoint', 'PersistentKeepalive'}:
            raise ValueError()
        for section, key in ((interface, 'PrivateKey'), (peer, 'PublicKey'), (peer, 'PresharedKey')):
            if key not in section and key == 'PresharedKey':
                continue
            if len(base64.b64decode(section[key], validate=True)) != 32:
                raise ValueError()
        addresses = [ipaddress.ip_interface(a.strip()) for a in interface['Address'].split(',')]
        if not addresses or not any(a.version == 4 for a in addresses):
            raise ValueError()
        mtu = int(interface.get('MTU', '1300'))
        keepalive = int(peer.get('PersistentKeepalive', '15'))
        if not 1280 <= mtu <= 1420 or not 0 <= keepalive <= 120:
            raise ValueError()
        endpoint = peer['Endpoint']
        if not re.fullmatch(r'[A-Za-z0-9.-]+:[0-9]{1,5}', endpoint):
            raise ValueError()
        if not 1 <= int(endpoint.rsplit(':', 1)[1]) <= 65535:
            raise ValueError()
        parsed = urlsplit(url)
        hostname = parsed.hostname
        if parsed.scheme != 'https' or parsed.username or parsed.password or parsed.port not in (None, 443):
            raise ValueError()
        if not hostname or not re.fullmatch(r'[A-Za-z0-9.-]+', hostname):
            raise ValueError()
        ips = sorted({r[4][0] for r in resolver(hostname, 443, socket.AF_INET, socket.SOCK_STREAM)})
        if not ips or len(ips) > 16 or any(not ipaddress.ip_address(ip).is_global for ip in ips):
            raise ValueError()
        # Do not honor broad 0/0 routes or VPN DNS. Only the feed host is routed.
        lines = ['[Interface]', 'PrivateKey = ' + interface['PrivateKey'],
                 'Address = ' + ', '.join(str(a) for a in addresses if a.version == 4),
                 'MTU = ' + str(mtu), '', '[Peer]', 'PublicKey = ' + peer['PublicKey']]
        if peer.get('PresharedKey'):
            lines.append('PresharedKey = ' + peer['PresharedKey'])
        lines.extend(['AllowedIPs = ' + ', '.join(ip + '/32' for ip in ips),
                      'Endpoint = ' + endpoint, 'PersistentKeepalive = ' + str(keepalive)])
        return '\n'.join(lines) + '\n', hostname, ips
    except (ValueError, KeyError, configparser.Error, OSError):
        raise PublicError('vpn_configuration_invalid') from None


# Run these fixed scripts as root; never execute hooks from a supplied config.
PIN_HOST = """import sys
from pathlib import Path
p=Path('/etc/hosts')
lines=[l for l in p.read_text().splitlines() if not l.endswith(' # xml-worker-vpn')]
lines.extend(ip+' '+sys.argv[1]+' # xml-worker-vpn' for ip in sys.argv[2:])
p.write_text('\\n'.join(lines)+'\\n')
"""
UNPIN_HOST = """from pathlib import Path
p=Path('/etc/hosts')
p.write_text('\\n'.join(l for l in p.read_text().splitlines() if not l.endswith(' # xml-worker-vpn'))+'\\n')
"""


def up():
    folder = root()
    config, hostname, ips = configuration(required('WIREGUARD_CONFIG'), required('PRIVATE_FEED_URL'))
    path = folder / (INTERFACE + '.conf')
    path.write_text(config); path.chmod(0o600)
    command(['sudo', '-n', 'wg-quick', 'up', str(path)], 'vpn_setup', 60)
    # Avoid a subsequent DNS answer selecting an un-routed address.
    command(['sudo', '-n', 'python3', '-c', PIN_HOST, hostname, *ips], 'vpn_host_pin', 30)


def down():
    path = root() / (INTERFACE + '.conf')
    failure = None
    try:
        command(['sudo', '-n', 'python3', '-c', UNPIN_HOST], 'vpn_host_restore', 30)
    except PublicError as error:
        failure = error
    try:
        # A missing interface means setup failed before tunnel creation.
        command(['sudo', '-n', 'sh', '-c',
                 'if ip link show xmlfeed >/dev/null 2>&1; then wg-quick down "$1"; fi',
                 'vpn-cleanup', str(path)], 'vpn_cleanup', 60)
    except PublicError as error:
        failure = error
    finally:
        path.unlink(missing_ok=True)
    if failure:
        raise failure


def health():
    command(['sudo', '-n', 'wg', 'show', INTERFACE, 'latest-handshakes'], 'vpn_handshake_check', 15)
    command(['sudo', '-n', 'wg', 'show', INTERFACE, 'transfer'], 'vpn_transfer_check', 15)
    handshakes = (root() / 'vpn_handshake_check.log').read_text().splitlines()
    transfers = (root() / 'vpn_transfer_check.log').read_text().splitlines()
    connected = any(int(line.split()[1]) > 0 for line in handshakes if len(line.split()) == 2)
    received = any(int(line.split()[1]) > 0 for line in transfers if len(line.split()) == 3)
    sent = any(int(line.split()[2]) > 0 for line in transfers if len(line.split()) == 3)
    print(json.dumps({'phase': 'vpn_health', 'handshake': connected,
                      'received_data': received, 'sent_data': sent}))


def probe():
    parsed = urlsplit(required('PRIVATE_FEED_URL'))
    hostname = parsed.hostname
    reachable = False
    try:
        with socket.create_connection((hostname, 443), timeout=15):
            reachable = True
    except OSError:
        pass
    health()
    if not reachable:
        raise PublicError('vpn_feed_unreachable')
    print(json.dumps({'phase': 'vpn_connectivity', 'status': 'passed'}))
    connection = http.client.HTTPSConnection(hostname, timeout=15, context=ssl.create_default_context())
    try:
        connection.connect()
        print(json.dumps({'phase': 'vpn_tls', 'status': 'passed'}))
    except (OSError, ssl.SSLError):
        connection.close()
        raise PublicError('vpn_tls_failed') from None
    try:
        path = parsed.path or '/'
        if parsed.query:
            path += '?' + parsed.query
        connection.request('HEAD', path, headers={'User-Agent': 'XML-JobRunner/1.0', 'Accept': 'application/xml,text/xml'})
        response = connection.getresponse()
        print(json.dumps({'phase': 'vpn_http', 'http_status': response.status}))
        if response.getheader('cf-mitigated', '').lower() == 'challenge':
            raise PublicError('http_challenge')
    except (OSError, http.client.HTTPException):
        raise PublicError('vpn_http_failed') from None
    finally:
        connection.close()


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['up', 'down', 'health', 'probe'])
    action = parser.parse_args().action
    try:
        {'up': up, 'down': down, 'health': health, 'probe': probe}[action]()
        return 0
    except PublicError as error:
        print(json.dumps({'phase': 'vpn', 'status': 'failed', 'category': error.category}))
    except Exception:
        print(json.dumps({'phase': 'vpn', 'status': 'failed', 'category': 'vpn_failed'}))
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
