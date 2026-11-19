import hashlib,json,platform,unittest
from pathlib import Path
from audit import ROOT,audit,canonical
from fixtures import clean,contaminated,near_only,POLICY
from snapshot import freeze,verify

def main():
    private=ROOT/'private';private.mkdir(exist_ok=True)
    out=ROOT/'reports';out.mkdir(exist_ok=True)
    result={};snapshots={}
    for name,records in [('clean',clean()),('contaminated',contaminated()),('near_only',near_only())]:
        (private/(name+'.json')).write_text(canonical(records),encoding='utf-8')
        result[name]=audit(records,POLICY);path=freeze(records,POLICY);snapshots[name]=verify(path)
        (out/(name+'-audit.json')).write_text(json.dumps(result[name],indent=2),encoding='utf-8')
    (private/'policy.json').write_text(canonical(POLICY),encoding='utf-8')
    if [result[n]['status'] for n in ('clean','contaminated','near_only')]!=['pass','fail','review']:raise RuntimeError('Authored scenario expectation failed')
    suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'))
    tests=unittest.TextTestRunner(verbosity=2).run(suite)
    if not tests.wasSuccessful():raise SystemExit(1)
    report=dict(scope='Original synthetic split-policy scenarios; not model accuracy or an independent leakage benchmark',
        tests_run=tests.testsRun,tests_passed=True,python=platform.python_version(),platform=platform.platform(),
        scenarios={k:dict(status=v['status'],records=v['records'],counts=v['counts'],input_sha256=v['input_sha256']) for k,v in result.items()},
        snapshot_reconstruction=snapshots,
        source_sha256={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in ('audit.py','snapshot.py','fixtures.py','pipeline.py')})
    (out/'verification.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    # JSON is escaped before embedding; UI uses textContent, not source HTML.
    data=json.dumps(result,ensure_ascii=True).replace('<','\\u003c')
    (out/'report.html').write_text(HTML.replace('__REPORT_DATA__',data),encoding='utf-8')
    lines=['# SplitSentinel measured results','','Original synthetic policy stress cases. Counts are findings, not unique leaked records.','',
           '| Scenario | Records | Status | Policy violations | Review findings |','|---|---:|---|---:|---:|']
    for name,r in result.items():lines.append(f"| {name} | {r['records']} | {r['status']} | {r['counts'].get('violation',0)} | {r['counts'].get('review',0)} |")
    lines+=['',f'{tests.testsRun} tests passed; all three snapshots reconstructed with identical logical reports.',
            'A pass only means the implemented checks found no violations of the supplied policy. It does not certify absence of all leakage. Near-text matches require human review. No ML model is trained or scored.']
    (out/'RESULTS.md').write_text('\n'.join(lines)+'\n',encoding='utf-8');print('\n'.join(lines),flush=True)
    print('SPLITSENTINEL CHECKS PASSED. Open reports/report.html for the local audit viewer.')

HTML='''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SplitSentinel audit report</title><style>body{background:#091525;color:#e9f3ff;font:16px system-ui;margin:0}main{max-width:1100px;margin:40px auto;padding:24px}h1{font-size:44px;margin:4px 0}.tag{color:#5cddbc}section{background:#12283d;border:1px solid #294b66;border-radius:16px;padding:24px;margin-top:24px}select{padding:10px;background:#0b1c2c;color:white;font:inherit;border-radius:8px}td,th{padding:10px;text-align:left;border-bottom:1px solid #2b4860}table{width:100%;border-collapse:collapse}.scroll{overflow:auto}.warning{color:#ffd391}code{overflow-wrap:anywhere}small{color:#a6c2d6}</style><main><p class="tag">ML DATASET SPLIT AUDIT</p><h1>SplitSentinel</h1><p>Inspect cross-split content, group identity and declared time boundaries.</p><p class="warning">Original synthetic examples. A pass is not a guarantee of no leakage. Similar text requires human review.</p><section><label>Scenario <select id="scenario"><option value="clean">Clean fixture</option><option value="contaminated">Contaminated fixture</option><option value="near_only">Near-duplicate review fixture</option></select></label><h2 id="status"></h2><p id="counts"></p><small>Input fingerprint <code id="hash"></code></small></section><section><h2>Findings and source record IDs</h2><div class="scroll"><table><thead><tr><th>Severity</th><th>Check</th><th>Record IDs</th><th>Evidence</th></tr></thead><tbody id="rows"></tbody></table></div><p id="empty"></p><small>Raw input text is omitted. Group-value hashes are linkable fingerprints, not anonymization. Time windows are start-inclusive and end-exclusive.</small></section></main><script>const reports=__REPORT_DATA__;function cell(row,text){let td=document.createElement('td');td.textContent=text;row.appendChild(td)}function show(){let r=reports[document.getElementById('scenario').value];document.getElementById('status').textContent=r.status.toUpperCase();document.getElementById('counts').textContent=r.records+' records · '+(r.counts.violation||0)+' policy violations · '+(r.counts.review||0)+' review findings';document.getElementById('hash').textContent=r.input_sha256;let target=document.getElementById('rows');target.replaceChildren();for(let f of r.findings){let tr=document.createElement('tr');cell(tr,f.severity);cell(tr,f.kind);cell(tr,f.row_ids.join(', '));let details={...f};delete details.kind;delete details.severity;delete details.row_ids;cell(tr,JSON.stringify(details));target.appendChild(tr)}document.getElementById('empty').textContent=r.findings.length?'':'No findings under the supplied policy.'}document.getElementById('scenario').onchange=show;show();</script></html>'''
if __name__=='__main__':main()
