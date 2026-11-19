import argparse,hashlib,json,os,re,shutil,tempfile
from pathlib import Path
from audit import ROOT,audit,canonical,digest

def file_sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def verify(path):
    path=Path(path);manifest=json.loads((path/'manifest.json').read_text())
    if path.name!=manifest['snapshot_id'] or digest(manifest['spec'])!=path.name:raise ValueError('Snapshot ID mismatch')
    if set(manifest['files'])!={'input.json','policy.json','audit.json'}:raise ValueError('Invalid snapshot manifest')
    for name,sha in manifest['files'].items():
        if file_sha(path/name)!=sha:raise ValueError('Snapshot artifact changed: '+name)
    source=json.loads((path/'input.json').read_text());policy=json.loads((path/'policy.json').read_text())
    saved=json.loads((path/'audit.json').read_text())
    if digest(source)!=manifest['spec']['input_sha256'] or digest(policy)!=manifest['spec']['policy_sha256'] or digest(saved)!=manifest['spec']['audit_sha256']:raise ValueError('Snapshot content identity mismatch')
    rebuilt=audit(source,policy)
    if digest(rebuilt)!=manifest['spec']['audit_sha256']:raise ValueError('Reconstruction mismatch; source, policy or auditor version changed')
    return dict(snapshot_id=path.name,logical_report_matches=True,status=rebuilt['status'])

def freeze(records,policy,root=None):
    root=Path(root or ROOT/'private/snapshots');root.mkdir(parents=True,exist_ok=True)
    records=sorted(records,key=lambda row:row['row_id']);report=audit(records,policy)
    spec=dict(input_sha256=digest(records),policy_sha256=digest(policy),audit_sha256=digest(report),auditor_sha256=report['auditor_sha256'])
    sid=digest(spec);dest=root/sid
    if dest.exists():verify(dest);return dest
    stage=Path(tempfile.mkdtemp(prefix='.building-',dir=root))
    try:
        for name,value in [('input.json',records),('policy.json',policy),('audit.json',report)]:
            (stage/name).write_text(canonical(value),encoding='utf-8')
        manifest=dict(snapshot_id=sid,spec=spec,files={n:file_sha(stage/n) for n in ('input.json','policy.json','audit.json')})
        (stage/'manifest.json').write_text(canonical(manifest),encoding='utf-8')
        os.rename(stage,dest);verify(dest);return dest
    finally:
        if stage.exists():
            if stage.resolve().parent!=root.resolve() or not stage.name.startswith('.building-'):raise ValueError('Unsafe staging cleanup')
            shutil.rmtree(stage)

def main():
    p=argparse.ArgumentParser();p.add_argument('--verify',required=True);args=p.parse_args()
    if not re.fullmatch('[a-f0-9]{64}',args.verify):raise ValueError('A full snapshot ID is required')
    print(json.dumps(verify(ROOT/'private/snapshots'/args.verify),indent=2))
if __name__=='__main__':main()
