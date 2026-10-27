# Separate experimental ML warning prototype

`ml_warning.py` is a standalone, standard-library-only presentation function.
It has no production integration, model loading, dataset reads, or network use.
Call `separate_ml_warning(existing_integer_risk_score, candidate_probability)`.

Existing risk classification stays SAFE (0–30), SUSPICIOUS (31–60), or UNSAFE
(61–100). The function accepts an already calculated score and never changes
the production hybrid formula. An ML warning neither promotes nor demotes it.
Risk scores must be integer JSON numbers; probability must be a finite numeric
value in [0, 1]. Invalid inputs raise generic ValueError rather than suppressing
warnings or defaulting to safety.

The exact experimental threshold is **0.40144790130467084**, inclusive, from
the private offline evaluation's `comparison.json`. It applies to the locally
trained candidate's phishing-class probability (label 1), not the 0–100 risk
score, the old production model, or an independently calibrated likelihood.

On 74,264 validation examples, this threshold measured 90.004% phishing recall,
52.165% precision, and **19.404% false-positive rate** (11,667 of 60,128 benign
examples). False-positive rate is the share of benign records warned about,
not the share of warnings that are wrong. About 10% of phishing records were
missed. These validation-selected results are not an independent performance
guarantee; deployment prevalence, drift, and warning fatigue can change utility.
Exact dataset version and upstream licensing remain unverified.

A warning does not confirm maliciousness. No warning does not establish safety.
The prototype is intended for a separately approved, non-blocking UI test,
with the risk classification and experimental warning shown separately.
It is not an automatic blocking decision. Future integration must ensure the
probability comes from the verified candidate with its matching feature order
and class mapping, and define explicit unavailable-model/error handling.

Synthetic checks only:

```powershell
.\backend\venv\Scripts\python.exe -B -m unittest discover -s backend/tests -p test_ml_warning.py -v
```
