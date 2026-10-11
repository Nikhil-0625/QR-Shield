"""
Diagnostic script — run this from your backend/ folder (with venv activated)
to figure out exactly why Instagram is scoring 99% phishing probability.

Usage:
    cd backend
    venv\\Scripts\\activate
    python diagnose_model.py
"""

import joblib
import re

ml_model = joblib.load("phishing_model_v2.pkl")

print("=" * 60)
print("STEP 1: What classes did this model learn?")
print("=" * 60)
print("model.classes_ =", ml_model.classes_)
print()
print("This tells you the exact label values the model was trained on.")
print("If you see [-1, 1] or [0, 1] etc., we need to know which number")
print("means 'phishing' and which means 'benign' from your training notebook.")
print()


def extract_ml_features(url):
    features = {}
    features['url_length'] = len(url)
    features['has_https'] = 1 if url.startswith('https') else 0
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_at'] = url.count('@')
    features['num_question_marks'] = url.count('?')
    features['num_equal'] = url.count('=')
    features['num_underscore'] = url.count('_')
    features['num_slash'] = url.count('/')
    features['has_ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['num_subdomains'] = url.count('.') - 1 if url.count('.') > 1 else 0
    return features


feature_order = ['url_length', 'has_https', 'num_dots', 'num_hyphens', 'num_at',
                  'num_question_marks', 'num_equal', 'num_underscore', 'num_slash',
                  'has_ip', 'num_digits', 'num_subdomains']

test_urls = {
    "Instagram (known legit)": "https://www.instagram.com",
    "Google (known legit)": "https://www.google.com",
    "Wikipedia (known legit)": "https://en.wikipedia.org/wiki/Main_Page",
    "Raw IP URL (classic phishing signal)": "http://192.168.1.1/login/verify.php",
    "Suspicious lookalike-style URL": "http://paypal-secure-login.verify-account.tk/update?id=12345",
    "Long messy URL with many params": "http://example.com/a/b/c/d?x=1&y=2&z=3&token=abcde12345&session=xyz",
}

print("=" * 60)
print("STEP 2: Raw prediction + full probability breakdown per URL")
print("=" * 60)

for label, url in test_urls.items():
    feats = extract_ml_features(url)
    vector = [[feats[f] for f in feature_order]]
    prediction = ml_model.predict(vector)[0]
    probabilities = ml_model.predict_proba(vector)[0]

    print(f"\n{label}")
    print(f"  URL: {url}")
    print(f"  Raw prediction (class label): {prediction}")
    for class_value, prob in zip(ml_model.classes_, probabilities):
        print(f"  P(class={class_value}) = {prob:.4f}")

print()
print("=" * 60)
print("HOW TO READ THIS")
print("=" * 60)
print("""
1. Check model.classes_ printed at the top. Whatever value your training
   notebook used to mean "phishing" (e.g. -1, or 1, or "phishing") is the
   one you should be indexing into predict_proba() for phishing_probability.

2. Look at the per-URL breakdown above. For clearly LEGITIMATE sites
   (Instagram, Google, Wikipedia), the probability for whichever class
   is "phishing" should ideally be LOW. If it's consistently near 99%
   for legit sites too, that's evidence the model isn't discriminating
   well on these structural features alone -- not necessarily a label bug.

3. If the raw predictions themselves (not just probabilities) label
   Instagram/Google as the phishing class, that's a stronger signal
   something is wrong with training (e.g. features computed differently
   during training vs. here, or a genuinely mislabeled dataset).

4. Compare: does the phishing-signal URL (raw IP, lookalike domain)
   actually score HIGHER than the legit ones? If yes, the model IS
   discriminating somewhat, just with a poorly calibrated scale --
   in that case your 70/30 rule-vs-ML weighting is already doing its
   job correctly, and this is a documented limitation, not a bug.
   If no -- if legit and phishing-style URLs score about the same --
   that's a real problem worth investigating in the training notebook.
""")