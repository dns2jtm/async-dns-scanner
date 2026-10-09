"""Unit tests for WHOIS parser."""

import unittest
from dns_scanner.whois import parse_whois_response, get_tld_whois_server


class TestWhoisParser(unittest.TestCase):

    def test_get_tld_whois_server(self):
        self.assertEqual(get_tld_whois_server("example.com"), "whois.verisign-grs.com")
        self.assertEqual(get_tld_whois_server("test.uk"), "whois.nic.uk")
        self.assertEqual(get_tld_whois_server("startup.io"), "whois.nic.io")
        self.assertEqual(get_tld_whois_server("deep.unknown"), "whois.iana.org")

    def test_parse_whois_registered_domain(self):
        raw = """
        Domain Name: EXAMPLE.COM
        Registry Domain ID: 2336799_DOMAIN_COM-VRSN
        Registrar: CSC CORPORATE DOMAINS, INC.
        Creation Date: 1995-08-14T04:00:00Z
        Registry Expiry Date: 2026-08-13T04:00:00Z
        Name Server: A.IANA-SERVERS.NET
        Name Server: B.IANA-SERVERS.NET
        """
        record = parse_whois_response("example.com", "whois.verisign-grs.com", raw)
        self.assertTrue(record.registered)
        self.assertEqual(record.registrar, "CSC CORPORATE DOMAINS, INC.")
        self.assertIn("a.iana-servers.net", record.name_servers)
        self.assertEqual(record.creation_date, "1995-08-14T04:00:00Z")

    def test_parse_whois_unregistered_domain(self):
        raw = "No match for domain \"NONEXISTENTXYZ12345.COM\"."
        record = parse_whois_response("nonexistentxyz12345.com", "whois.verisign-grs.com", raw)
        self.assertFalse(record.registered)


if __name__ == "__main__":
    unittest.main()
