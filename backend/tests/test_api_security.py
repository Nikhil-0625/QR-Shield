"""Local ASGI security tests: memory-only SQLite, synthetic JWTs, no model/network."""
import asyncio
import io
import json
import secrets
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from jose import jwt
import test_history_authorization as harness


class ApiSecurityTests(harness.HistoryAuthorizationTests):
    @classmethod
    def setUpClass(cls):
        with patch("dotenv.load_dotenv", return_value=False), patch.dict("os.environ", {"CORS_ALLOWED_ORIGINS":"http://localhost:5500,http://127.0.0.1:5500"}):
            super().setUpClass()
    def api(self, path, method='GET', token=None, body=b'', headers=None, query=''):
        async def run():
            messages=[]
            sent=False
            async def receive():
                nonlocal sent
                if not sent:
                    sent=True
                    return {'type':'http.request','body':body,'more_body':False}
                await asyncio.Event().wait()
            async def send(message): messages.append(message)
            h=list(headers or [])
            if not any(k.lower()==b'host' for k,_ in h): h.append((b'host',b'localhost:8000'))
            if token is not None: h.append((b'authorization',('Bearer '+token).encode()))
            try:
                await self.main.app({'type':'http','asgi':{'version':'3.0','spec_version':'2.4'},'http_version':'1.1','method':method,'scheme':'http','path':path,'raw_path':path.encode(),'query_string':query.encode(),'root_path':'','headers':h,'client':('127.0.0.1',1234),'server':('test',80)},receive,send)
            except Exception:
                if not messages: raise
            start=next(m for m in messages if m['type']=='http.response.start')
            return start['status'],b''.join(m.get('body',b'') for m in messages if m['type']=='http.response.body'),dict(start['headers'])
        return asyncio.run(run())

    def signed(self, claims, key=None, algorithm='HS256'):
        return jwt.encode(claims,key or self.signing_key,algorithm=algorithm)

    def test_token_rejection_matrix_all_protected_routes(self):
        valid={'sub':'a@example.test','exp':datetime.now(timezone.utc)+timedelta(minutes=5)}
        tokens=[None,'garbage','a.b.c',self.token('a@example.test',True),self.signed(valid,secrets.token_urlsafe(48)),self.signed(valid,algorithm='HS384'),self.signed({'sub':'a@example.test'}),self.signed({'exp':valid['exp']}),self.signed({'sub':123,'exp':valid['exp']}),self.signed({'sub':'','exp':valid['exp']}),self.signed({'sub':'a@example.test','exp':[]}),self.signed({'sub':'a@example.test','exp':None})]
        for path,method in [('/history','GET'),('/report/11','GET'),('/scan','POST')]:
            for i,token in enumerate(tokens):
                with self.subTest(path=path,case=i):
                    code,body,_=self.api(path,method,token)
                    self.assertIn(code,(401,403))
                    self.assertNotIn(self.signing_key.encode(),body)
                    self.assertNotIn(b'Traceback',body)

    def test_client_user_id_cannot_change_history_or_report_owner(self):
        before=self.snapshot()
        token=self.token('a@example.test')
        code,body,_=self.api('/history',token=token,query='user_id=2&email=b@example.test&scan_id=22',headers=[(b'x-user-id',b'2')])
        self.assertEqual(code,200)
        self.assertEqual([r['id'] for r in json.loads(body)],[11])
        for record in [22,33,999999]:
            code,body,_=self.api('/report/'+str(record),token=token,query='user_id=2')
            self.assertEqual((code,json.loads(body)),(404,{'detail':'Report not found'}))
        self.assertEqual(self.snapshot(),before)

    def test_invalid_inputs_do_not_crash_or_expose_details(self):
        token=self.token('a@example.test')
        for path,method,body,headers in [('/report/not-an-integer','GET',b'',[]),('/scan','POST',b'',[]),('/login','POST',b'{bad',[(b'content-type',b'application/json')]),('/register','POST',b'{}',[(b'content-type',b'application/json')])]:
            code,response,_=self.api(path,method,token,body,headers)
            self.assertEqual(code,422)
            self.assertNotIn(b'Traceback',response)
        for data in [b'',b'not an image']:
            multipart=b'--local\r\nContent-Disposition: form-data; name="file"; filename="bad.png"\r\nContent-Type: image/png\r\n\r\n'+data+b'\r\n--local--\r\n'
            code,_,_=self.api('/scan','POST',token,multipart,[(b'content-type',b'multipart/form-data; boundary=local')])
            self.assertEqual(code,400)

    def test_real_hashing_registration_and_login_token(self):
        password='Local!Synthetic123'
        def auth(path,values):
            return self.api(path,'POST',body=json.dumps(values).encode(),headers=[(b'content-type',b'application/json')])
        code,body,_=auth('/register',{'email':'new@example.test','password':password,'user_id':2})
        self.assertEqual(json.loads(body)['status'],'success')
        db=self.database.SessionLocal()
        try: hashed=db.query(self.database.User).filter_by(email='new@example.test').one().hashed_password
        finally: db.close()
        self.assertTrue(hashed.startswith('$2'))
        self.assertNotEqual(hashed,password)
        self.assertTrue(self.main.verify_password(password,hashed))
        self.assertFalse(self.main.verify_password('wrong',hashed))
        self.assertNotEqual(self.main.hash_password(password),hashed)
        _,body,_=auth('/login',{'email':'new@example.test','password':password})
        response=json.loads(body)
        self.assertEqual(set(response),{'status','access_token','token_type'})
        claims=jwt.decode(response['access_token'],self.signing_key,algorithms=['HS256'])
        self.assertEqual(claims['sub'],'new@example.test')
        self.assertTrue(3500 < claims['exp']-datetime.now(timezone.utc).timestamp() <=3600)
        for path in ['/login','/register']:
            _,body,_=auth(path,{'email':'new@example.test','password':'wrong'})
            self.assertNotIn(hashed.encode(),body)
            self.assertNotIn(password.encode(),body)
            self.assertNotIn(self.signing_key.encode(),body)

    def test_logout_is_client_only_token_can_be_reused(self):
        self.assertFalse(any(r.path=='/logout' for r in self.main.app.routes))
        token=self.token('a@example.test')
        self.assertEqual(self.api('/history',token=token)[0],200)
        self.assertEqual(self.api('/history',token=token)[0],200)

    def test_cors_untrusted_origin_rejected(self):
        headers=[(b'origin',b'https://untrusted.example'),(b'access-control-request-method',b'GET'),(b'access-control-request-headers',b'authorization')]
        code,_,response=self.api('/history','OPTIONS',headers=headers)
        self.assertEqual(code,400)
        self.assertNotIn(b'access-control-allow-origin',response)

    def test_scan_owner_comes_from_token_not_form_or_query(self):
        import cv2
        import numpy as np
        image=cv2.imencode('.png',np.full((32,32,3),255,dtype=np.uint8))[1].tobytes()
        body=b'--local\r\nContent-Disposition: form-data; name="user_id"\r\n\r\n2\r\n--local\r\nContent-Disposition: form-data; name="file"; filename="test.png"\r\nContent-Type: image/png\r\n\r\n'+image+b'\r\n--local--\r\n'
        with patch.object(self.main,'decode_qr',return_value='Synthetic local text'), patch.object(self.main,'analyze_tampering',return_value={'tampering_score':0,'tampering_reasons':[]}):
            code,response,_=self.api('/scan','POST',self.token('a@example.test'),body,[(b'content-type',b'multipart/form-data; boundary=local')],query='user_id=2')
        self.assertEqual(code,200)
        record_id=json.loads(response)['scan_id']
        db=self.database.SessionLocal()
        try: self.assertEqual(db.query(self.database.ScanRecord).filter_by(id=record_id).one().user_id,1)
        finally: db.close()
        self.assertEqual(self.api('/report/'+str(record_id),token=self.token('b@example.test'))[0],404)

    def test_cors_allows_local_frontend(self):
        for origin in ['http://localhost:5500','http://127.0.0.1:5500']:
            code,_,headers=self.api('/history','OPTIONS',headers=[(b'origin',origin.encode()),(b'access-control-request-method',b'GET'),(b'access-control-request-headers',b'authorization')])
            self.assertEqual(code,200)
            self.assertEqual(headers[b'access-control-allow-origin'],origin.encode())

    def test_upload_limits_before_opencv_allocation(self):
        import asyncio
        import io
        from fastapi import UploadFile, HTTPException
        from PIL import Image
        image=io.BytesIO();Image.new('RGB',(1,1)).save(image,format='PNG')
        import struct,zlib
        pixels=bytearray(image.getvalue());pixels[16:24]=struct.pack('>II',5000,5000);pixels[29:33]=struct.pack('>I',zlib.crc32(pixels[12:29]))
        for data in [b'x'*(5*1024*1024+1),bytes(pixels)]:
            with patch.object(self.main.cv2,'imdecode') as decode:
                with self.assertRaises(HTTPException) as error:
                    asyncio.run(self.main.scan_qr(UploadFile(filename='synthetic.png',file=io.BytesIO(data)),current_user='a@example.test',expected_vpa=None))
                self.assertEqual(error.exception.status_code,413);decode.assert_not_called()

    def test_long_passwords_do_not_hash_or_crash(self):
        for route in ['/login','/register']:
            with patch.object(self.main,'hash_password') as hashing:
                code,body,_=self.api(route,'POST',body=json.dumps({'email':'long@example.test','password':'A!1'+chr(233)*40}).encode(),headers=[(b'content-type',b'application/json')])
                self.assertEqual(code,200);self.assertEqual(json.loads(body)['status'],'error');hashing.assert_not_called()

    def test_short_secret_is_rejected_without_real_artifacts(self):
        import sys,os,joblib
        with patch.dict(sys.modules,{'database':self.database}), patch.dict(os.environ,{'JWT_SECRET_KEY':'short','CORS_ALLOWED_ORIGINS':'http://localhost:5500'}), patch('dotenv.load_dotenv',return_value=False), patch.object(joblib,'load',return_value=object()):
            with self.assertRaisesRegex(RuntimeError,'at least 32 bytes'):
                harness.load_module('short_secret_synthetic_main','main.py')
