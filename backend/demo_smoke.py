"""Container acceptance smoke; no database writes or outbound requests."""
import argparse
import io
import json
import cv2
import numpy as np
from PIL import Image
from pyzbar.pyzbar import decode
import qrcode
from reportlab.pdfgen import canvas


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model",action="store_true")
    args=parser.parse_args()
    payload="http://paypal-login.example.com/verify"
    stream=io.BytesIO()
    qrcode.make(payload).save(stream,format="PNG")
    image=cv2.imdecode(np.frombuffer(stream.getvalue(),dtype=np.uint8),cv2.IMREAD_COLOR)
    assert decode(image)[0].data.decode()==payload, "ZBar round trip failed"
    assert hasattr(cv2,"wechat_qrcode_WeChatQRCode"), "OpenCV contrib decoder missing"
    cv2.wechat_qrcode_WeChatQRCode()
    pdf=io.BytesIO()
    document=canvas.Canvas(pdf)
    document.drawString(30,800,"Synthetic offline QR Shield acceptance check")
    document.save()
    assert pdf.getvalue().startswith(b"%PDF")
    result={"zbar_qr_roundtrip":True,"opencv_contrib":True,"pdf":True}
    if args.model:
        import joblib
        import sklearn
        import pandas as pd
        import warnings
        from sklearn.exceptions import InconsistentVersionWarning
        from demo_runtime import load_production_model
        from legacy_ml_features import FEATURE_NAMES,legacy_feature_vector
        from ml_probability import phishing_probability
        assert sklearn.__version__=="1.9.0", "Use the model's original scikit-learn version"
        with warnings.catch_warnings():
            warnings.simplefilter("error",InconsistentVersionWarning)
            model=load_production_model(joblib.load)
        assert list(model.feature_names_in_)==list(FEATURE_NAMES)
        assert set(model.classes_)=={-1,1}, "Unexpected production class labels"
        frame=pd.DataFrame([legacy_feature_vector(payload)],columns=FEATURE_NAMES)
        probability=phishing_probability(model.classes_,model.predict_proba(frame),phishing_label=-1)[0]
        assert 0 <= probability <= 1
        result.update(model_hash_and_schema=True,classes=model.classes_.tolist())
    print(json.dumps(result))


if __name__=="__main__": main()
