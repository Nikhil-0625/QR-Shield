"""Offline-only registrable-domain grouping; not imported by production code."""
import hashlib
import ipaddress
from pathlib import Path

from publicsuffix2 import PublicSuffixList


LOCAL_PSL = Path(__file__).resolve().parent / "venv/Lib/site-packages/whois/data/public_suffix_list.dat"
PSL_SHA256 = "603d1bd1919a2c20aaac863095b00a0aa22c7a146387468e15690045edc0b8d4"


class OfflineDomainParser:
    def __init__(self):
        data = LOCAL_PSL.read_bytes()  # Missing or changed snapshots fail closed.
        if hashlib.sha256(data).hexdigest() != PSL_SHA256:
            raise ValueError("Local PSL snapshot checksum does not match the reviewed version")
        self.psl = PublicSuffixList(data.decode("utf-8").splitlines(), idna=True)

    def group(self, hostname):
        """Return a typed group identifier, or reject a nonregistrable hostname."""
        host = hostname.strip().rstrip(".").lower()
        try:
            return "ip:" + ipaddress.ip_address(host).compressed
        except ValueError:
            pass
        host = host.encode("idna").decode("ascii")
        suffix = self.psl.get_tld(host, wildcard=True, strict=True)
        domain = self.psl.get_sld(host, wildcard=True, strict=True)
        if not suffix or not domain or domain == suffix:
            raise ValueError("Hostname has no recognized registrable domain")
        return "domain:" + domain
