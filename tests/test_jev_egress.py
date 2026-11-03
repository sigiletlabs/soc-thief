"""The Jev egress helper writes a proposal and never alters the source policy."""

import os
import tempfile
import unittest
from ipaddress import IPv4Address
from pathlib import Path
from unittest.mock import patch

from soc_thief.jev_egress import JevEgressError, main, propose, target, write_proposal


POLICY = ('table inet soc_thief_egress {\n'
          '\tchain output {\n'
          '\t\tmeta skuid 123 counter log prefix "soc-thief-drop: " level info drop '
          'comment "soc-thief: no external egress"\n'
          '\t}\n}\n')
PUBLIC_TEST_ADDRESS = str(IPv4Address(0x09090909))
LOOPBACK_TEST_ADDRESS = str(IPv4Address(0x7F000001))


class JevEgressTests(unittest.TestCase):
    def test_proposal_adds_one_rule_before_drop(self):
        result = propose(POLICY, [PUBLIC_TEST_ADDRESS])
        self.assertEqual(result.count('comment "Jev trial HTTPS, review required"'), 1)
        self.assertLess(result.index('Jev trial HTTPS'), result.index('soc-thief: no external egress'))
        self.assertEqual(result.replace(f'\t\tip daddr {{ {PUBLIC_TEST_ADDRESS} }} tcp dport 443 accept '
                                        'comment "Jev trial HTTPS, review required"\n', ''), POLICY)

    def test_invalid_or_repeat_proposal_fails(self):
        for policy, addresses in ((POLICY, [LOOPBACK_TEST_ADDRESS]), (POLICY, []),
                                  (POLICY.replace('soc-thief: no external egress', 'other'), [PUBLIC_TEST_ADDRESS]),
                                  (propose(POLICY, [PUBLIC_TEST_ADDRESS]), [PUBLIC_TEST_ADDRESS])):
            with self.subTest(policy=policy[:20], addresses=len(addresses)), self.assertRaises(JevEgressError):
                propose(policy, addresses)

    def test_writer_creates_private_file_without_changing_source(self):
        with tempfile.TemporaryDirectory() as root:
            source, output = Path(root) / 'policy', Path(root) / 'proposal'
            source.write_text(POLICY)
            with patch('soc_thief.jev_egress.socket.getaddrinfo', return_value=[
                (2, 1, 6, '', (PUBLIC_TEST_ADDRESS, 443))]) as lookup:
                write_proposal(source, output)
            self.assertEqual(lookup.call_args.args[0], 'api.typesafe.ai')
            self.assertEqual(source.read_text(), POLICY)
            self.assertIn('Jev trial HTTPS', output.read_text())
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)
            with self.assertRaises(JevEgressError):
                write_proposal(source, output)

    def test_writer_resolves_the_chosen_route(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / 'policy'
            source.write_text(POLICY)
            with patch('soc_thief.jev_egress.socket.getaddrinfo', return_value=[
                (2, 1, 6, '', (PUBLIC_TEST_ADDRESS, 443))]) as lookup:
                for route, host in (('vercel', 'ai-gateway.vercel.sh'), ('openrouter', 'openrouter.ai'),
                                    ('typesafe', 'api.typesafe.ai')):
                    write_proposal(source, Path(root) / route, route)
                    self.assertEqual(lookup.call_args.args[0], host)
                with self.assertRaises(JevEgressError):
                    write_proposal(source, Path(root) / 'bad', 'https://evil.invalid')

    def test_custom_base_url_follows_its_host_and_port(self):
        self.assertEqual(target(base_url='https://jev.example.invalid/api'), ('jev.example.invalid', 443))
        self.assertEqual(target(base_url='https://jev.example.invalid:8443'), ('jev.example.invalid', 8443))
        self.assertIsNone(target(base_url='http://127.0.0.1:8080'))
        for bad in ('http://jev.example.invalid', 'http://localhost:8080', 'https://u:p@jev.example.invalid'):
            with self.subTest(bad=bad), self.assertRaises(JevEgressError):
                target(base_url=bad)
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / 'policy'
            source.write_text(POLICY)
            with patch('soc_thief.jev_egress.socket.getaddrinfo', return_value=[
                (2, 1, 6, '', (PUBLIC_TEST_ADDRESS, 8443))]) as lookup:
                write_proposal(source, Path(root) / 'custom', base_url='https://jev.example.invalid:8443')
            self.assertEqual(lookup.call_args.args[:2], ('jev.example.invalid', 8443))
            self.assertIn('tcp dport 8443 accept', (Path(root) / 'custom').read_text())
            # A loopback server needs no rule: nothing is resolved or written.
            with patch('soc_thief.jev_egress.socket.getaddrinfo') as lookup, \
                    patch('builtins.print'):
                self.assertEqual(main(['--source', str(source), '--output', str(Path(root) / 'local'),
                                       '--base-url', 'http://127.0.0.1:8080']), 0)
            lookup.assert_not_called()
            self.assertFalse((Path(root) / 'local').exists())


if __name__ == '__main__':
    unittest.main()
