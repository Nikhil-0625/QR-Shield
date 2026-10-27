// Synthetic browser harness. Inject inline after the demo script; no API calls.
async function runPredictionUITests() {
  let checks = 0;
  const assert = condition => { if (!condition) { document.documentElement.dataset.predictionFailure = String(checks); throw new Error('Synthetic UI failure'); } checks++; };
  const originalFetch = window.fetch;
  const input = document.getElementById('prediction-url');
  const status = document.getElementById('live-status');
  const result = document.getElementById('live-result');
  const event = {preventDefault() {}};
  const success = probability => ({experimental: true, production_risk_evaluated: false,
    risk_score: null, risk_classification: null, candidate_phishing_probability: probability,
    ...separateMLWarning(0, probability), risk_score: null, risk_classification: null});
  try {
    assert(document.documentElement.dataset.checks === '45');
    input.value = 'https://example.invalid/synthetic';
    let resolve;
    window.fetch = (endpoint, options) => {
      assert(endpoint === 'http://127.0.0.1:8766/experimental/predict');
      assert(options.method === 'POST' && options.credentials === 'omit' && options.redirect === 'error');
      assert(options.cache === 'no-store' && options.referrerPolicy === 'no-referrer');
      assert(JSON.parse(options.body).url === input.value);
      return new Promise(done => { resolve = done; });
    };
    const pending = analyzePrediction(event);
    assert(document.getElementById('analyze-button').disabled);
    assert(!document.getElementById('loading').hidden);
    assert(document.getElementById('prediction-form').getAttribute('aria-busy') === 'true');
    await analyzePrediction(event); // Duplicate submit must not send another call.
    resolve({ok: true, json: async () => success(WARNING_THRESHOLD)});
    await pending;
    assert(!result.hidden && document.getElementById('live-warning').textContent === 'Experimental warning active');
    assert(!document.getElementById('analyze-button').disabled && document.getElementById('loading').hidden);
    window.fetch = async () => ({ok: true, json: async () => success(0.1)});
    await analyzePrediction(event);
    assert(document.getElementById('live-warning').textContent === 'No experimental warning');
    for (const code of [403,413,422,503,500]) {
      window.fetch = async () => ({ok: false, status: code});
      await analyzePrediction(event);
      assert(result.hidden && status.textContent.length > 20);
    }
    for (const name of ['TypeError','AbortError']) {
      window.fetch = async () => { const error = new Error('synthetic-private-marker'); error.name = name; throw error; };
      await analyzePrediction(event);
      assert(result.hidden && !status.textContent.includes('synthetic-private-marker'));
      assert(!document.getElementById('analyze-button').disabled);
    }
    for (const data of [{}, {...success(.9),risk_score:20}, {...success(.9),warning_threshold:.4},
                        {...success(.9),experimental_ml_warning:false}]) {
      window.fetch = async () => ({ok: true, json: async () => data});
      await analyzePrediction(event);
      assert(result.hidden && status.textContent.includes('unexpected response'));
    }
    window.fetch = async () => ({ok: true, json: async () => { throw new Error('bad JSON'); }});
    await analyzePrediction(event);
    assert(result.hidden);
    const injected = {...success(.9),warning_explanation:'<img src=x onerror=alert(1)>'};
    window.fetch = async () => ({ok: true,json:async () => injected});
    await analyzePrediction(event);
    assert(document.getElementById('live-explanation').textContent === injected.warning_explanation);
    assert(document.getElementById('live-explanation').children.length === 0);
    window.fetch = async () => { throw new Error('Should not submit'); };
    for (const value of ['not-a-url','ftp://example.invalid','https://user:pass@example.invalid']) {
      input.value = value;
      await analyzePrediction(event);
      assert(result.hidden && !predictionBusy);
    }
    const labels=['SAFE','SAFE','SUSPICIOUS','UNSAFE'];
    scenarios.forEach((_,i) => { renderScenario(i); assert(document.getElementById('classification').textContent===labels[i]); });
    assert(document.documentElement.scrollWidth <= window.innerWidth);
    document.documentElement.dataset.predictionTests = String(checks);
  } finally { window.fetch = originalFetch; }
}
runPredictionUITests().catch(() => { document.documentElement.dataset.predictionTests = 'failed'; });
