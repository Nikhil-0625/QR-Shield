"""Offline hostname/PSL parsing and explainable lexical indicators (no network I/O)."""
from functools import lru_cache
from importlib.resources import files
import ipaddress
import re
from urllib.parse import urlsplit, unquote
from publicsuffix2 import PublicSuffixList
from rapidfuzz import fuzz
from brand_config import PROTECTED_BRANDS, LOOKALIKE_SIMILARITY_THRESHOLD


GENERIC_ACTION_QUALIFIERS = frozenset({
    'login', 'signin', 'verify', 'verification', 'password', 'credential',
    'credentials', 'secure', 'security', 'account', 'banking', 'payment',
    'pay', 'portal', 'kyc', 'support', 'online', 'service', 'help', 'update'
})


def hostname(value):
    try:
        parsed = urlsplit(value if '://' in value else '//' + value)
        host = (parsed.hostname or '').rstrip('.').lower()
        try: return ipaddress.ip_address(host).compressed
        except ValueError: return host.encode('idna').decode('ascii')
    except (TypeError, ValueError, UnicodeError):
        return ''


def educational_host(host):
    return any(host == suffix or host.endswith('.' + suffix)
               for suffix in ('example.com','example.net','example.org','example','test','invalid'))


@lru_cache(maxsize=1)
def suffix_parser():
    # Use python-whois's installed snapshot; never fetch a PSL at scan time.
    data = files('whois').joinpath('data/public_suffix_list.dat').read_text(encoding='utf-8')
    return PublicSuffixList(data.splitlines(), idna=True)


def registered_domain(value):
    host = hostname(value)
    if not host: return None
    try: ipaddress.ip_address(host); return None
    except ValueError: pass
    labels = host.split('.')
    # Reserved educational suffixes have no public registration but can be parsed structurally.
    if labels[-1] in ('example','test','invalid'):
        return '.'.join(labels[-2:]) if len(labels) >= 2 else None
    parser = suffix_parser()
    suffix = parser.get_tld(host, strict=True)
    domain = parser.get_sld(host, strict=True)
    return domain if domain and domain != suffix else None


def official_host(host):
    return any(host == domain or host.endswith('.' + domain)
               for brand in PROTECTED_BRANDS for domain in brand['domains'])


def brand_match(value):
    host = hostname(value)
    if not host or official_host(host): return None, 0
    try: ipaddress.ip_address(host); return None, 0
    except ValueError: pass
    domain = registered_domain(host)
    label = domain.split('.')[0] if domain else ''
    subdomains = host[:-len(domain)].rstrip('.').split('.') if domain else []
    # Exact token boundaries in subdomains catch paypal-login.example.com without
    # matching incidental substrings such as 'ola' inside an ordinary word.
    words = {word for part in subdomains for word in re.split('[-_]', part) if word}
    candidates = [label] + [word for word in re.split('[-_]', label) if word]

    path_tokens = set()
    if isinstance(value, str) and ('://' in value or '/' in value):
        try:
            path = urlsplit(value if '://' in value else '//' + value).path
            path_tokens = set(re.findall(r'[a-z0-9]+', unquote(path).lower()))
        except Exception:
            pass

    all_context = words | set(candidates) | path_tokens
    best, score = None, 0

    for brand in PROTECTED_BRANDS:
        token = brand['token']
        distinctive = brand.get('distinctive_tokens', [])
        requires_context = brand.get('requires_context', len(token) <= 3)
        brand_qualifiers = brand.get('qualifiers', set()) | GENERIC_ACTION_QUALIFIERS

        # 1. Distinctive multi-token brand indicators (e.g. licindia, olacabs, goindigo, onlinesbi)
        if any(dt in words or dt in candidates for dt in distinctive):
            return brand['name'], 100

        # 2. Subdomains exact token matching
        if token in words:
            if requires_context:
                has_context = bool((all_context - {token}) & brand_qualifiers)
                if has_context:
                    return brand['name'], 100
            else:
                return brand['name'], 100

        # 3. Registered domain and label matching
        for candidate in candidates:
            if token in candidate and candidate != token:
                continue
            similarity = fuzz.ratio(token, candidate)
            if candidate != token and (len(token) < 5 or len(candidate) < 5):
                continue
            if candidate == token and requires_context:
                # Require contextual indicators so generic words/short SLDs like 'indigo.ca'
                # or 'lic.co.nz' are not flagged without brand impersonation indicators
                has_context = bool((all_context - {candidate}) & brand_qualifiers)
                if not has_context:
                    continue
            if similarity > score:
                best, score = brand['name'], similarity

    return (best, score) if score >= LOOKALIKE_SIMILARITY_THRESHOLD else (None, score)


def structural_findings(url, matched_brand=None):
    try:
        parsed = urlsplit(url)
    except ValueError:
        return [{'source':'rule','category':'phishing','name':'Malformed URL Structure','points':10,'reason':'The URL cannot be parsed reliably; network verification is unavailable.'}]
    findings=[]
    def add(name, points, reason, category='phishing'):
        findings.append({'source':'rule','category':category,'name':name,'points':points,'reason':reason})
    if parsed.scheme.lower() == 'http':
        add('HTTP Connection',20,'This URL uses unencrypted HTTP rather than HTTPS; information sent over this connection may not be protected in transit. Insecure transport is a transport security risk, not proof of phishing.','transport')
    if parsed.username is not None or parsed.password is not None:
        add('Embedded URL Credentials',15,'Text before @ is not the destination hostname; the actual hostname is ' + hostname(url) + '.','phishing')
    try: ipaddress.ip_address(parsed.hostname or ''); ip_host=True
    except ValueError: ip_host=False
    # Login/verify paths are ordinary on legitimate sites. Treat them as contextual
    # evidence only alongside a brand mismatch or IP-address destination.
    tokens = set(re.findall(r'[a-z0-9]+',unquote(parsed.path).lower()))
    if tokens & {'login','signin','verify','verification','password','credential','credentials'} and (matched_brand or ip_host):
        add('Sensitive Action Pattern',10,'A login, password or verification path appears alongside a brand mismatch or IP-address host. This is a potential risk indicator, not proof of credential theft.','phishing')
    try:
        if parsed.port is not None and parsed.port not in (80,443) and (matched_brand or parsed.username is not None):
            add('Unusual Destination Port',5,'This already suspicious destination also uses a nonstandard web port.','phishing')
    except ValueError:
        add('Invalid URL Port',10,'The URL contains an invalid destination port; network verification cannot be completed.','phishing')
    return findings
