// Production function tests with synthetic DOM/fetch/clipboard; no real accounts.
(async () => {
    let checks = 0;
    const check = (condition, name) => {
        document.documentElement.dataset.phaseBLastCheck = name;
        if (!condition) throw new Error(name);
        checks++;
    };
    const node = () => ({ value: '', innerText: '', textContent: '', disabled: false, hidden: true,
        style: {}, attributes: {}, setAttribute(k, v) { this.attributes[k] = v; },
        focus() { this.focused = true; }, select() { this.selected = true; } });
    function dom() {
        const nodes = new Map();
        return { getElementById(id) { if (!nodes.has(id)) nodes.set(id, node()); return nodes.get(id); } };
    }
    const loginScript = [...LOGIN_SOURCE.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)].at(-1)[1];
    function login(fetcher, supportsAbort = true, storageFails = false) {
        const document = dom(), calls = [], timers = new Map(), stored = {};
        document.getElementById('email').value = 'synthetic@example.test';
        document.getElementById('password').value = 'Synthetic!Only123';
        document.getElementById('submit-btn').innerText = 'Sign In';
        const location = { hostname: 'localhost', protocol: 'http:' };
        let nextTimer = 0;
        class Controller { constructor() { this.signal = { aborted: false }; } abort() { this.signal.aborted = true; } }
        const api = new Function('document', 'window', 'location', 'fetch', 'localStorage', 'setTimeout', 'clearTimeout', 'AbortController',
            loginScript + ';return {handleSubmit,toggleFormMode};')(
            document, {location}, location, (...args) => { calls.push(args); return fetcher(...args); },
            { setItem(k,v) { if (storageFails) throw new Error('storage denied'); stored[k]=v; } },
            (fn, ms) => { const id=++nextTimer; timers.set(id,{fn,ms}); return id; },
            id => timers.delete(id), supportsAbort ? Controller : undefined);
        return { ...api, document, calls, timers, stored, location,
            message: () => document.getElementById('message').innerText,
            fire(ms) { const [id,timer]=[...timers].find(([,t])=>t.ms===ms); timers.delete(id); timer.fn(); } };
    }
    const response = (data, status=200) => ({ok:status>=200&&status<300,status,json:async()=>data});
    const restored = env => {
        check(!env.document.getElementById('submit-btn').disabled,'button restored');
        check(env.document.getElementById('submit-btn').attributes['aria-busy']==='false','busy state cleared');
        check(![...env.timers.values()].some(t=>t.ms===15000),'deadline cleared');
    };
    let env=login(async()=>response({status:'success',access_token:'synthetic-token'}));
    await env.handleSubmit();
    check(env.stored.access_token==='synthetic-token','existing token storage');
    check(env.calls.length===1 && env.calls[0][0].endsWith('/login'),'existing login endpoint');
    const payload=JSON.parse(env.calls[0][1].body);
    check(payload.email==='synthetic@example.test'&&payload.password==='Synthetic!Only123','unchanged request shape');
    env.fire(1000);check(env.location.href==='scan.html','existing redirect');restored(env);
    check(env.document.getElementById('submit-btn').innerText==='Sign In','original label restored');
    env=login(async()=>response({status:'success'}));env.toggleFormMode();await env.handleSubmit();
    check(env.calls[0][0].endsWith('/register'),'existing registration endpoint');
    check(env.message().includes('Registered successfully'),'registration success');restored(env);
    env.fire(1200);check(env.document.getElementById('submit-btn').innerText==='Login','registration returns to login');
    for (const data of [null,[],{},'text',{status:'other'},{status:'success'},{status:'success',access_token:''},{status:'success',access_token:5}]) {
        env=login(async()=>response(data));await env.handleSubmit();
        check(env.message().includes('unexpected response'),'unexpected payload rejected');
        check(!env.stored.access_token,'invalid success does not store a token');restored(env);
    }
    env=login(async()=>{throw new Error('sensitive internal exception');});await env.handleSubmit();
    check(env.message().includes('Could not reach'),'network failure');check(!env.message().includes('sensitive'),'network details redacted');restored(env);
    for (const exception of [new SyntaxError('malformed JSON'),new SyntaxError('<html>private response</html>')]) {
        env=login(async()=>({ok:true,status:200,json:async()=>{throw exception;}}));await env.handleSubmit();
        check(env.message().includes('unreadable response'),'non-JSON and malformed JSON');restored(env);
    }
    for (const [status,fragment] of [[400,'check your details'],[401,'email and password'],[403,'restricted'],[422,'check your details'],[429,'Too many attempts'],[500,'temporarily unavailable'],[503,'temporarily unavailable'],[404,'could not be completed']]) {
        env=login(async()=>({ok:false,status,json:async()=>{throw new Error('must not parse HTTP error body');}}));await env.handleSubmit();
        check(env.message().includes(fragment),'HTTP error explained safely');restored(env);
    }
    for (const data of [{status:'error'},{status:'error',message:'Traceback sensitive server detail'},{status:'error',message:{secret:'value'}}]) {
        env=login(async()=>response(data));await env.handleSubmit();
        check(env.message().includes('Unable to sign in'),'missing/untrusted message fallback');
        check(!env.message().includes('sensitive'),'server details redacted');restored(env);
    }
    env=login(async()=>response({status:'error',message:'Email already registered'}));env.toggleFormMode();await env.handleSubmit();
    check(env.message()==='Email already registered','known registration feedback retained');restored(env);
    for (const supportsAbort of [true,false]) {
        for (const pendingBody of [true,false]) {
            env=login(async()=> pendingBody ? {ok:true,status:200,json:()=>new Promise(()=>{})} : new Promise(()=>{}),supportsAbort);
            const pending=env.handleSubmit();
            check(env.document.getElementById('submit-btn').disabled,'pending request disables button');
            await env.handleSubmit();env.toggleFormMode();check(env.calls.length===1,'no duplicate submission');
            env.fire(15000);await pending;
            check(env.message().includes('timed out'),'fetch/body deadline');
            check(!env.stored.access_token,'no token on timeout');
            if(supportsAbort)check(env.calls[0][1].signal.aborted,'AbortController invoked');
            restored(env);
        }
    }
    env=login(async()=>response({status:'success',access_token:'synthetic-token'}),true,true);await env.handleSubmit();
    check(env.message().includes('could not save'),'storage failure is not a network error');restored(env);
    let finish;
    env=login(()=>new Promise(resolve=>{finish=resolve;}));let pending=env.handleSubmit();env.fire(15000);await pending;
    finish(response({status:'success',access_token:'late-token'}));await Promise.resolve();await Promise.resolve();
    check(!env.stored.access_token&&env.message().includes('timed out'),'late response cannot sign in');

    const copyScript=SCAN_SOURCE.slice(SCAN_SOURCE.indexOf('    let copyableQrContent = null;'),SCAN_SOURCE.indexOf('    function getPlainResultReason('));
    function clipboard(secure, writer) {
        const document=dom();
        return {...new Function('document','window','navigator',copyScript+';return {resetCopyContent,copyQrContent};')(
            document,{isSecureContext:secure},writer?{clipboard:{writeText:writer}}:{}),document};
    }
    const exact='  upi://pay?pa=synthetic@upi&pn=%E2%82%B9\r\n\t<svg> & value  ';
    let copied;
    let copy=clipboard(true,async text=>{copied=text;});copy.resetCopyContent(exact);await copy.copyQrContent();
    check(copied===exact,'clipboard receives exact original including whitespace/CRLF');
    check(copy.document.getElementById('copy-content-status').textContent==='QR content copied.','accessible success');
    for (const secure of [true,false]) {
        copy=clipboard(secure,secure?async()=>{throw new Error('permission denied');}:null);
        copy.resetCopyContent(exact);await copy.copyQrContent();
        const fallback=copy.document.getElementById('copy-content-fallback');
        check(!fallback.hidden&&fallback.value===exact,'safe selectable fallback');
        check(fallback.focused&&fallback.selected,'fallback focused and selected');
        check(copy.document.getElementById('copy-content-status').textContent.includes('Automatic copying is unavailable'),'honest failure feedback');
        check(!copy.document.getElementById('copy-content-btn').disabled,'copy button restored');
        copy.resetCopyContent();check(fallback.hidden&&fallback.value==='','reset clears fallback');
        check(copy.document.getElementById('copy-content-btn').disabled,'reset disables copying');
    }
    copy=clipboard(true,null);copy.resetCopyContent(exact);await copy.copyQrContent();
    check(!copy.document.getElementById('copy-content-fallback').hidden,'missing Clipboard API fallback');
    for(const fail of [false,true]) {
        let settle;
        copy=clipboard(true,()=>new Promise((resolve,reject)=>{settle=fail?reject:resolve;}));
        copy.resetCopyContent(exact);pending=copy.copyQrContent();copy.resetCopyContent(exact);settle();await pending;
        check(copy.document.getElementById('copy-content-status').textContent==='','stale copy completion ignored');
    }
    check(SCAN_SOURCE.includes('onclick="QRShieldLinkWarning.open()"'),'warning-before-opening control retained');
    check(SCAN_SOURCE.includes('id="copy-content-status" role="status" aria-live="polite"'),'copy feedback live region');
    check(SCAN_SOURCE.includes('resetCopyContent(data.decoded_content)'),'copies original decoded field');

    // Copy Summary reuses production verdict/intent helpers; clipboard and timers are synthetic.
    const summaryScript = [
        SCAN_SOURCE.slice(SCAN_SOURCE.indexOf('    function getAssessmentContext('), SCAN_SOURCE.indexOf('    function getVerdictDetails(')),
        SCAN_SOURCE.slice(SCAN_SOURCE.indexOf('    function getUpiIntentBanner('), SCAN_SOURCE.indexOf('    function createUpiDirectionBanner(')),
        SCAN_SOURCE.slice(SCAN_SOURCE.indexOf('    function getHumanVerdict('), SCAN_SOURCE.indexOf('    function showResults('))
    ].join('\n');
    function summaryClipboard(secure, writer) {
        const document=dom(), timers=new Map();let nextTimer=0;
        return {...new Function('document','window','navigator','setTimeout','clearTimeout',summaryScript+
            ';return {buildCopySummary,resetCopySummary,copySummary};')(
            document,{isSecureContext:secure},writer?{clipboard:{writeText:writer}}:{},
            (fn,ms)=>{const id=++nextTimer;timers.set(id,{fn,ms});return id;},id=>timers.delete(id)),document,timers};
    }
    const safeSummary='\u{1F6E1}\uFE0F QR Shield: Likely Safe. You can open this.';
    const cautionSummary="\u{1F6E1}\uFE0F QR Shield: Be careful. Don't enter passwords or payment details. Open only if you trust the sender.";
    const unknownSummary="\u{1F6E1}\uFE0F QR Shield: Can't tell. Don't pay or log in. Verify the sender first.";
    let summary=summaryClipboard(true,async text=>{copied=text;});
    const urlResult={decoded_content:'https://example.test',final_url:'https://example.test',risk_score:0,rule_score:0,ml_phishing_probability:10};
    for(const [patch,expected] of [
        [{},safeSummary],[{risk_score:30},safeSummary],[{risk_score:31},cautionSummary],
        [{risk_score:60},cautionSummary],[{risk_score:100},cautionSummary],
        [{ml_phishing_probability:100},unknownSummary],[{ml_phishing_probability:null},unknownSummary],
        [{rule_score:70,ml_phishing_probability:10},unknownSummary]
    ]) check(summary.buildCopySummary({...urlResult,...patch})===expected,'exact summary follows existing displayed verdict');
    check(summary.buildCopySummary({...urlResult,decoded_content:''})==='','empty content cannot be summarized');
    const upi={decoded_content:'upi://pay?pa=demo@upi',upi_details:{payee_vpa:'demo@upi',payee_name:'Demo Merchant',vpa_format_valid:true,currency:'INR',amount:'125.00',amount_valid:true}};
    let payment=summary.buildCopySummary(upi);
    check(payment===cautionSummary+'\nUPI: YOU ARE PAYING \u20B9125.00 TO Demo Merchant\nPayee: Demo Merchant\nAmount: \u20B9125.00','UPI includes intent, exact payee and amount');
    payment=summary.buildCopySummary({...upi,upi_details:{...upi.upi_details,mode:'collect'}});
    check(payment.startsWith(cautionSummary)&&payment.includes('THIS WILL REQUEST MONEY FROM YOU'),'collect warning retained');
    payment=summary.buildCopySummary({...upi,upi_details:{...upi.upi_details,amount:null}});
    check(payment.includes('YOU ARE PAYING Demo Merchant')&&payment.endsWith('Amount: Not fixed'),'open amount is explicit');
    payment=summary.buildCopySummary({...upi,upi_details:{...upi.upi_details,conflicting_parameters:{pa:['a@upi','b@upi']}}});
    check(payment.startsWith(unknownSummary)&&payment.includes('PAYMENT DETAILS CONFLICT'),'conflicting UPI cannot be summarized as safe');
    payment=summary.buildCopySummary({...upi,upi_details:{...upi.upi_details,vpa_format_valid:false}});
    check(payment.startsWith(unknownSummary),'malformed UPI remains unknown');
    payment=summary.buildCopySummary({...upi,upi_details:{...upi.upi_details,payee_name:'<script>alert(1)</script> & Shop'}});
    check(payment.includes('Payee: <script>alert(1)</script> & Shop'),'clipboard preserves literal plain text without HTML interpretation');
    summary.resetCopySummary(safeSummary);await summary.copySummary();
    check(copied===safeSummary,'clipboard receives exact summary');
    check(summary.document.getElementById('copy-summary-status').textContent==='Copied to clipboard!','exact accessible success toast');
    check(!summary.document.getElementById('copy-summary-btn').disabled&&summary.document.getElementById('copy-summary-btn').attributes['aria-busy']==='false','summary button restored');
    const toast=[...summary.timers.values()][0];check(toast.ms===3000,'success toast is temporary');toast.fn();
    check(summary.document.getElementById('copy-summary-status').textContent==='','toast clears');
    for(const [secure,writer] of [[false,null],[true,null],[true,async()=>{throw new Error('private denial');}]]) {
        summary=summaryClipboard(secure,writer);summary.resetCopySummary(cautionSummary);await summary.copySummary();
        const message=summary.document.getElementById('copy-summary-status').textContent;
        check(message.startsWith('Could not copy summary.')&&!message.includes('private denial'),'honest safe clipboard failure');
        check(!summary.document.getElementById('copy-summary-btn').disabled,'failure permits retry');
    }
    for(const fail of [false,true]) {
        let settle,calls=0;
        summary=summaryClipboard(true,()=>{calls++;return new Promise((resolve,reject)=>{settle=fail?reject:resolve;});});
        summary.resetCopySummary(safeSummary);pending=summary.copySummary();await summary.copySummary();
        check(calls===1,'pending copy cannot be duplicated');
        summary.resetCopySummary();settle();await pending;
        check(summary.document.getElementById('copy-summary-status').textContent===''&&summary.document.getElementById('copy-summary-btn').disabled,'reset invalidates stale copy completion');
        check(summary.timers.size===0,'reset leaves no stale toast timer');
    }
    check(/id="report-btn"[^>]*>Download PDF Report<\/button>\s*<button[^>]*id="copy-summary-btn"/.test(SCAN_SOURCE),'summary adjacent to PDF action');
    check(SCAN_SOURCE.includes('id="copy-summary-status" class="summary-toast" role="status" aria-live="polite"'),'summary toast is a polite live region');

    // Diagnostic output excludes all URLs, credentials, API resources and storage.
    const secret='private-token-password-query';
    const entries={navigation:[{name:secret,type:'navigate',requestStart:10,responseStart:50,responseEnd:60,domInteractive:70,domContentLoadedEventEnd:80,loadEventEnd:90}],resource:[
        {name:'https://private.example/theme.css?'+secret,initiatorType:'link',startTime:1,duration:2,transferSize:3,encodedBodySize:4,decodedBodySize:5},
        {name:'https://private.example/api/login?'+secret}],paint:[{name:'first-contentful-paint',startTime:75}]};
    const report=new Function('performance','document','URL','return ('+PERF_SOURCE.replace(/;\s*$/,'') + ')' )({getEntriesByType:type=>entries[type]||[]},{readyState:'complete'},URL);
    check(report.resources.length===1&&report.resources[0].asset==='theme.css','diagnostic static-asset allowlist');
    check(!JSON.stringify(report).includes(secret)&&!JSON.stringify(report).includes('private.example'),'diagnostic redacts URLs and queries');
    check(report.navigation.responseWaitMs===40,'diagnostic timing arithmetic');
    document.documentElement.dataset.phaseBChecks=String(checks);
})().catch(()=>{document.documentElement.dataset.phaseBFailure='Phase B assertion failed';});
