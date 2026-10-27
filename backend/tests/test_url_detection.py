"""Requirement 1 URL indicators: isolated routes/DB and mocked network evidence."""
import io,json,socket
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
from PIL import Image
import test_history_authorization as harness
import test_api_security as api_harness


class UrlDetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with patch('dotenv.load_dotenv',return_value=False):harness.HistoryAuthorizationTests.setUpClass.__func__(cls)
    @classmethod
    def tearDownClass(cls):cls.engine.dispose()
    setUp=harness.HistoryAuthorizationTests.setUp
    token=harness.HistoryAuthorizationTests.token
    api=api_harness.ApiSecurityTests.api

    def scan(self,payload,probability=.5,real_decode=False,headers=(),expected_status=200):
        image=io.BytesIO()
        if real_decode:
            import qrcode
            qrcode.make(payload).save(image,format='PNG')
        else:Image.new('RGB',(8,8),'white').save(image,format='PNG')
        body=b'--local\r\nContent-Disposition: form-data; name="file"; filename="synthetic.png"\r\nContent-Type: image/png\r\n\r\n'+image.getvalue()+b'\r\n--local--\r\n'
        model=SimpleNamespace(classes_=[-1,1],predict_proba=Mock(return_value=[[probability,1-probability]]))
        from contextlib import ExitStack
        import os
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, {'QR_SCANNER_ML_ENABLED': 'true'}))
            stack.enter_context(patch.object(self.main,'ml_model',model))
            if not real_decode:stack.enter_context(patch.object(self.main,'decode_qr',return_value=payload))
            stack.enter_context(patch.object(self.main,'analyze_tampering',return_value={'tampering_score':0,'tampering_reasons':[]}))
            def redirect_fixture(url, max_hops=5, allow_network=True):
                restricted = self.main.restricted_demo()
                permitted = allow_network and not restricted
                state = 'unavailable' if permitted else 'blocked'
                details = {'status':state,'original_url':url,'final_url':url,'redirect_count':None,
                    'observed_redirects':0,'chain':[url],'hops':[],'final_response_status':None,
                    'reason':'Network responses are not fixture data.' if permitted else 'Restricted demo: all external destination checks are disabled.' if restricted else 'Network checks are disabled for this offline or restricted request.'}
                return [url], details
            def tls_fixture(url, allow_network=True, include_details=False):
                restricted = self.main.restricted_demo()
                permitted = allow_network and not restricted
                is_http = url.lower().startswith('http://')
                details = {'status':'not_applicable' if is_http else 'unavailable' if permitted else 'blocked',
                    'valid':None,'reason':'No TLS result is fabricated in the offline test fixture.' if permitted else 'Restricted demo: all external destination checks are disabled.' if restricted else 'Network checks are disabled for this offline or restricted request.',
                    'hostname':'synthetic.example'}
                return details if include_details else details['valid']
            stack.enter_context(patch.object(self.main,'trace_redirects',side_effect=redirect_fixture))
            stack.enter_context(patch.object(self.main,'check_https_valid',side_effect=tls_fixture))
            # Every DNS attempt fails locally; no actual network or WHOIS is permitted.
            stack.enter_context(patch.object(self.main.socket,'getaddrinfo',side_effect=socket.gaierror('synthetic unavailable')))
            stack.enter_context(patch.object(self.main.requests,'get',side_effect=AssertionError('HTTP forbidden')))
            stack.enter_context(patch.object(self.main.whois,'whois',side_effect=AssertionError('WHOIS forbidden')))
            code,raw,_=self.api('/scan','POST',self.token('a@example.test'),body,
                [(b'content-type',b'multipart/form-data; boundary=local'),*headers])
        self.assertEqual(code,expected_status,raw)
        return json.loads(raw)

    def test_transport_check_metadata_preserves_http_and_offline_states(self):
        http = self.scan('http://paypal-login.example.com/verify')
        self.assertEqual(http['https_check_status'], 'not_applicable')
        self.assertIsNone(http['https_valid'])
        https = self.scan('https://paypal.example/verify', headers=((b'x-qr-shield-offline', b'1'),))
        self.assertEqual(https['https_check_status'], 'blocked')
        self.assertEqual(https['redirect_check_status'], 'blocked')
        self.assertIsNone(https['https_valid'])
        self.assertEqual(https['registered_domain'], 'paypal.example')

    def test_wikipedia_subdomain_uses_canonical_registered_domain(self):
        url = 'https://en.wikipedia.org/wiki/QR_code'
        result = self.scan(url, headers=((b'x-qr-shield-offline', b'1'),))
        self.assertEqual(self.main.parse_hostname(url), 'en.wikipedia.org')
        self.assertEqual(self.main.registered_domain('en.wikipedia.org'), 'wikipedia.org')
        self.assertEqual(result['domain'], 'en.wikipedia.org')
        self.assertEqual(result['registered_domain'], 'wikipedia.org')

    def test_misleading_subdomains_and_lookalike_domains(self):
        for url in ['http://paypal-login.example.com/verify','https://paypal.com.example.com/login','http://paypal.example/verify','https://paypa1.example/verify']:
            with self.subTest(url=url):
                result=self.scan(url)
                self.assertEqual(result['lookalike_brand'],'PayPal')
                names={r['name'] for r in result['risk_breakdown']}
                self.assertIn('Possible Brand Impersonation',names)
                self.assertIn('Sensitive Action Pattern',names)
                reason=next(r['reason'] for r in result['risk_breakdown'] if r['name']=='Possible Brand Impersonation')
                self.assertIn(result['registered_domain'],reason)
                self.assertNotIn('steals credentials',reason)

    def test_official_and_ordinary_subdomains_avoid_false_brand_flags(self):
        for host in ['accounts.google.com','login.paypal.com','en.wikipedia.org','api.service.com','chocolate.example','shop.example.com']:
            with self.subTest(host=host):
                self.assertIsNone(self.main.check_lookalike(host)[0])
        result=self.scan('https://accounts.google.com/login')
        self.assertEqual(result['rule_score'],0)
        self.assertIsNone(result['https_valid'])

    def test_public_suffix_wildcard_exception_private_and_ip_parsing(self):
        cases={'shop.merchant.co.uk':'merchant.co.uk','x.merchant.blogspot.com':'merchant.blogspot.com','x.y.ck':'x.y.ck','x.www.ck':'www.ck','paypal-login.example.com':'example.com','paypal.example':'paypal.example','https://WWW.PAYPAL.COM.:443/login':'paypal.com','192.0.2.1':None,'co.uk':None}
        for host,expected in cases.items():
            with self.subTest(host=host):self.assertEqual(self.main.get_root_domain(host),expected)

    def test_http_is_independent_of_dns_and_no_https_upgrade_request(self):
        result=self.scan('HTTP://paypal-login.example.com/verify')
        names={r['name'] for r in result['risk_breakdown']}
        self.assertIn('HTTP Connection',names)
        self.assertNotIn('HTTPS Validation Failed',names)
        self.assertEqual(result['registered_domain'],'example.com')
        with patch.object(self.main.requests,'get',side_effect=AssertionError('HTTP must not be upgraded')):
            self.assertIsNone(self.main.check_https_valid('http://www.wikipedia.org/'))
        self.assertIn('risk_score',self.scan('HTTPS://www.wikipedia.org/'))

    def test_tls_remains_unavailable_even_if_legacy_validation_is_overridden(self):
        blocked = {"status": "unavailable", "valid": None, "reason": "synthetic", "hostname": "wikipedia.org"}
        with patch.object(self.main, 'probe_https', return_value=blocked) as probe:
            self.assertIsNone(self.main.check_https_valid('https://wikipedia.org/'))
            probe.assert_called_once_with('https://wikipedia.org/', allow_network=True)

    def test_educational_destinations_never_attempt_dns(self):
        with patch.object(self.main.socket,'getaddrinfo',side_effect=AssertionError('Educational DNS forbidden')):
            for url in ['http://paypal-login.example.com/verify','http://paypal.example/verify']:
                allowed,reason=self.main.validate_outbound_url(url)
                self.assertFalse(allowed);self.assertIn('educational',reason)

    def test_contextual_structures_and_observed_redirects(self):
        result=self.scan('https://paypal.com@evil.test/verify')
        self.assertIn('Embedded URL Credentials',{r['name'] for r in result['risk_breakdown']})
        ip=self.scan('http://192.0.2.1/verify')
        self.assertIn('IP Address URL',{r['name'] for r in ip['risk_breakdown']})
        _,findings=self.main.calculate_rule_contributions(None,None,None,['https://one.test/','http://two.test/'], 'http://two.test/')
        self.assertIn('HTTPS Downgrade Redirect',{r['name'] for r in findings})
        _,single=self.main.calculate_rule_contributions(None,None,None,['https://one.test/'],'https://one.test/')
        self.assertFalse(any('Redirect' in r['name'] for r in single))
        _,upgrade=self.main.calculate_rule_contributions(None,True,None,['http://one.test/','https://one.test/'],'https://one.test/',original_url='http://one.test/')
        self.assertIn('original QR destination',next(r['reason'] for r in upgrade if r['name']=='HTTP Connection'))

    def test_real_qr_decode_and_upi_text_compatibility(self):
        for payload in ['http://paypal-login.example.com/verify','Plain educational text','upi://pay?pa=synthetic@upi&pn=Test']:
            result=self.scan(payload,real_decode=True)
            self.assertEqual(result['decoded_content'],payload)
            if not payload.startswith('http'):self.assertNotIn('risk_score',result)
            if payload.startswith('upi:'):self.assertIn('upi_comparison',result)


if __name__=='__main__':unittest.main()
