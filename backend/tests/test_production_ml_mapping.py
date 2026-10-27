"""Production ML mapping through ASGI; synthetic images, memory DB, no network/model load."""
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from PIL import Image
import test_history_authorization as harness
import test_api_security as api_harness


class ProductionMlMappingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with patch('dotenv.load_dotenv',return_value=False):
            harness.HistoryAuthorizationTests.setUpClass.__func__(cls)
    @classmethod
    def tearDownClass(cls):cls.engine.dispose()
    setUp=harness.HistoryAuthorizationTests.setUp
    token=harness.HistoryAuthorizationTests.token
    snapshot=harness.HistoryAuthorizationTests.snapshot
    api=api_harness.ApiSecurityTests.api

    def scan(self, classes, probabilities):
        image=io.BytesIO();Image.new('RGB',(8,8),'white').save(image,format='PNG')
        body=b'--local\r\nContent-Disposition: form-data; name="file"; filename="synthetic.png"\r\nContent-Type: image/png\r\n\r\n'+image.getvalue()+b'\r\n--local--\r\n'
        model=SimpleNamespace(classes_=classes,predict_proba=Mock(return_value=probabilities))
        with patch.dict('os.environ', {'QR_SCANNER_ML_ENABLED': 'true'}),patch.object(self.main,'ml_model',model),patch.object(self.main,'decode_qr',return_value='https://example.invalid/verify'),patch.object(self.main,'analyze_tampering',return_value={'tampering_score':0,'tampering_reasons':[]}),patch.object(self.main,'validate_outbound_url',return_value=(False,'synthetic offline test')),patch.object(self.main.requests,'get',side_effect=AssertionError('Network forbidden')),patch.object(self.main.whois,'whois',side_effect=AssertionError('Network forbidden')):
            code,raw,_=self.api('/scan','POST',self.token('a@example.test'),body,[(b'content-type',b'multipart/form-data; boundary=local')])
        return code,json.loads(raw),model

    def test_verified_phishing_class_minus_one_in_both_class_orders(self):
        for classes,values,expected in [([-1,1],[[.9,.1]],90),([-1,1],[[.1,.9]],10),([1,-1],[[.1,.9]],90),([1,-1],[[.9,.1]],10)]:
            with self.subTest(classes=classes,values=values):
                code,result,model=self.scan(classes,values)
                self.assertEqual(code,200)
                self.assertEqual(result['ml_phishing_probability'],expected)
                self.assertAlmostEqual(result['score_explanation']['ml_probability'],expected/100)
                self.assertEqual(result['risk_score'],round(.3*expected))
                self.assertEqual(result['score_explanation']['rule_weight'],.7)
                self.assertEqual(result['score_explanation']['ml_weight'],.3)
                model.predict_proba.assert_called_once()
                db=self.database.SessionLocal()
                try:self.assertEqual(float(db.query(self.database.ScanRecord).filter_by(id=result['scan_id']).one().ml_phishing_probability),expected)
                finally:db.close()

    def test_missing_unexpected_and_duplicate_labels_fail_without_persisting(self):
        before=self.snapshot()
        for classes in [[],[1],[-1],[0,1],[-1,0],[-1,1,2],[-1,-1],[1,1],['phishing','benign'],[True,-1],[False,-1],None]:
            with self.subTest(classes=classes):
                code,result,_=self.scan(classes,[[.9,.1]])
                self.assertEqual(code,503)
                self.assertEqual(result,{'detail':'ML analysis unavailable; scan classification was not completed'})
                self.assertNotIn('risk_label',result)
                self.assertEqual(self.snapshot(),before)

    def test_invalid_probability_outputs_fail_without_persisting(self):
        before=self.snapshot()
        for probabilities in [[],[[.9]],[[float('nan'),.1]],[[1.2,-.2]],[[.1,.1]],[[True,False]],[[.9,.1],[.1,.9]],None]:
            with self.subTest(probabilities=probabilities):
                code,result,_=self.scan([-1,1],probabilities)
                self.assertEqual(code,503)
                self.assertNotIn('risk_label',result)
                self.assertEqual(self.snapshot(),before)


if __name__=='__main__':unittest.main()
