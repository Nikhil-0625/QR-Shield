// Synthetic DOM/network checks of production privacy functions. No real records.
(async () => {
    let checks = 0;
    const check = (ok, name) => {
        document.documentElement.dataset.privacyLastCheck = name;
        if (!ok) throw new Error(name);
        checks++;
    };
    function dom() {
        const nodes = new Map();
        return {getElementById(id) {
            if (!nodes.has(id)) nodes.set(id, {checked:false,disabled:false,textContent:'',value:'',style:{}});
            return nodes.get(id);
        }};
    }
    const clearSource = DASHBOARD_SOURCE.slice(DASHBOARD_SOURCE.indexOf('        async function clearAllHistory()'),
        DASHBOARD_SOURCE.indexOf('        document.getElementById("clear-history-btn").addEventListener'));
    function dashboard(confirm, fetcher) {
        const document=dom(), calls=[], confirmations=[], timers=new Map(); let reloads=0;
        const historyModal={confirm(settings){confirmations.push(settings);return confirm(settings);}};
        const api = new Function('document','historyModal','fetch','getAccessToken','loadHistory','renderRecentScans','setTimeout','clearTimeout','AbortController',
            'const API_URL="/api";let historyBusy=false,clearingHistory=false,currentHistory=[1],historyCursor=1,historyNext=2,historyBack=[1],activeHistoryFilter="all";'+
            clearSource+';return {clearAllHistory,setHistoryBusy(value){historyBusy=value;}};')(
                document,historyModal,(...args)=>{calls.push(args);return fetcher(...args);},()=> 'synthetic-token',async()=>{reloads++;},()=>{},
                (fn)=>{timers.set(1,fn);return 1;},id=>timers.delete(id),AbortController);
        return {...api,document,calls,confirmations,timers,reloads:()=>reloads};
    }
    let env=dashboard(settings=>{
        check(settings.title==='Delete History'&&settings.message==='Delete all your scan history? This cannot be undone.'&&settings.proceedLabel==='Proceed','exact modal confirmation');
        return Promise.resolve(false);
    },async()=>{throw Error();});
    await env.clearAllHistory();check(env.calls.length===0,'cancel sends no deletion');
    check(!env.document.getElementById('clear-history-btn').disabled&&env.timers.size===0,'cancel restores controls without deadline');
    check(env.document.getElementById('clear-history-status').textContent==='','cancel does not claim deletion started');

    let choose;
    env=dashboard(()=>new Promise(resolve=>{choose=resolve;}),async()=>{throw Error();});
    const choosing=env.clearAllHistory();
    await env.clearAllHistory();
    check(env.confirmations.length===1&&env.calls.length===0,'pending confirmation prevents duplicate modal and deletion');
    check(env.document.getElementById('clear-history-btn').disabled&&env.timers.size===0,'pending confirmation reserves action without starting deadline');
    check(env.document.getElementById('clear-history-status').textContent==='','pending confirmation does not show deleting feedback');
    choose(false);await choosing;
    check(!env.document.getElementById('clear-history-btn').disabled&&env.calls.length===0,'pending cancellation restores button without request');

    env=dashboard(()=>Promise.reject(Error('private modal detail')),async()=>{throw Error();});
    await env.clearAllHistory();
    check(!env.document.getElementById('clear-history-btn').disabled&&env.timers.size===0&&env.calls.length===0,'modal failure restores controls without request');
    check(env.document.getElementById('clear-history-status').textContent.startsWith('Could not confirm deletion.')&&!env.document.getElementById('clear-history-status').textContent.includes('private modal detail'),'modal failure gives non-sensitive feedback');

    env=dashboard(()=>new Promise(resolve=>{choose=resolve;}),async()=>{throw Error();});
    const waitingForHistory=env.clearAllHistory();
    env.setHistoryBusy(true);choose(true);await waitingForHistory;
    check(env.calls.length===0&&env.timers.size===0,'history load during confirmation prevents concurrent deletion');
    check(env.document.getElementById('clear-history-btn').disabled,'history load keeps clear action disabled after confirmation');

    env=dashboard(()=>true,async()=>{throw Error();});
    env.setHistoryBusy(true);await env.clearAllHistory();
    check(env.confirmations.length===0&&env.calls.length===0,'busy history does not open confirmation or delete');

    env=dashboard(()=>true,async()=>({ok:true,json:async()=>({deleted_count:2})}));
    await env.clearAllHistory();
    check(env.calls.length===1&&env.calls[0][0]==='/api/history'&&env.calls[0][1].method==='DELETE','correct deletion request');
    check(env.calls[0][1].headers.Authorization==='Bearer synthetic-token','authenticated deletion');
    check(env.reloads()===1&&env.document.getElementById('clear-history-status').textContent==='Your scan history was cleared.','success refresh and feedback');
    check(!env.document.getElementById('clear-history-btn').disabled&&env.timers.size===0,'button and deadline restored');
    for (const fetcher of [async()=>{throw Error('private internal detail');},async()=>({ok:false}),async()=>({ok:true,json:async()=>{throw SyntaxError();}}),async()=>({ok:true,json:async()=>({})})]) {
        env=dashboard(()=>true,fetcher);await env.clearAllHistory();
        check(env.reloads()===0&&env.document.getElementById('clear-history-status').textContent.startsWith('Could not confirm deletion.'),'failure feedback without false success');
        check(!env.document.getElementById('clear-history-btn').disabled&&env.timers.size===0,'failure restores controls');
    }
    let resolve;
    env=dashboard(()=>true,()=>new Promise(r=>resolve=r));
    const pending=env.clearAllHistory();await Promise.resolve();await env.clearAllHistory();
    check(env.calls.length===1,'duplicate deletion prevented');
    resolve({ok:true,json:async()=>({deleted_count:0})});await pending;
    const noticeSource=SCAN_SOURCE.slice(SCAN_SOURCE.indexOf('    function updatePrivateScanNotice()'),SCAN_SOURCE.indexOf('    async function scanImage()'));
    const scanSource=SCAN_SOURCE.slice(SCAN_SOURCE.indexOf('    async function scanImage()'),SCAN_SOURCE.indexOf('    function beginAnalysisActivity()'));
    for (const privateScan of [true,false]) {
        const document=dom();document.getElementById('private-scan').checked=privateScan;
        new Function('document',noticeSource+';updatePrivateScanNotice();')(document);
        check(document.getElementById('private-scan-status').textContent===(privateScan?'Private scan is ON — this scan will not be saved.':'Private scan is OFF — this scan will be saved to your history.'),'exact toggle copy');
        let submitted;
        const run=new Function('document','fetch','FormData',
            'let isAnalyzing=false,selectedFile=new Blob(["synthetic"]),currentMode="upload",currentScanId=null;const window={},API_URL="/api",SCAN_ENDPOINT="/scan",token="synthetic-token",statusMsg={style:{}};const updateScanButtonState=()=>{},beginAnalysisActivity=()=>{},stopAnalysisActivity=()=>{},completeAnalysisActivity=()=>{},showResults=()=>{},setAnalysisError=()=>{};'+scanSource+';return scanImage();');
        await run(document,async(url,opts)=>{submitted=opts;return {ok:true,status:200,json:async()=>({status:'success',decoded_content:'synthetic',scan_id:privateScan?null:7})};},FormData);
        check(submitted.body.get('private_scan')===String(privateScan),'real scan form passes explicit boolean');
        check(submitted.headers.Authorization==='Bearer synthetic-token','scan auth preserved');
        check(!document.getElementById('private-scan').disabled,'privacy toggle restored after scan');
    }
    check(DASHBOARD_SOURCE.includes('Your scans are stored in your account. Only you can see them. You can clear them anytime.'),'history notice');
    document.documentElement.dataset.privacyChecks=String(checks);
})().catch(error=>{document.documentElement.dataset.privacyError=error.message;});
