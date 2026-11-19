"""Bounded dataset split-policy auditor. Does not train or score an ML model."""
import argparse,hashlib,itertools,json,re,sys,unicodedata
from collections import Counter,defaultdict
from datetime import datetime,timezone
from pathlib import Path

VERSION='split-policy-v1'
SPLITS=('train','validation','test')
FIELDS={'row_id','split','entity_id','source_group','event_at','text'}
ROOT=Path(__file__).resolve().parent

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)
def digest(value):return hashlib.sha256(canonical(value).encode()).hexdigest()
def normalize(text):return ' '.join(unicodedata.normalize('NFKC',text).casefold().split())
def timestamp(text):
    if not isinstance(text,str):raise ValueError('Timestamp must be text')
    dt=datetime.fromisoformat(text.replace('Z','+00:00'))
    if dt.tzinfo is None or dt.utcoffset().total_seconds()!=0:raise ValueError('Explicit UTC timestamp required')
    return dt.astimezone(timezone.utc)

def validate(records,policy):
    if not isinstance(records,list) or not 1<=len(records)<=500:raise ValueError('Expected 1..500 records')
    if not isinstance(policy,dict) or set(policy)!={'version','disjoint_fields','time_windows','near_threshold'} or type(policy['version']) is not int or policy['version']!=1:raise ValueError('Unsupported policy schema')
    if not isinstance(policy['disjoint_fields'],list) or len(set(policy['disjoint_fields']))!=len(policy['disjoint_fields']) or not set(policy['disjoint_fields'])<={'entity_id','source_group'}:raise ValueError('Invalid disjoint fields')
    if not isinstance(policy['near_threshold'],(int,float)) or isinstance(policy['near_threshold'],bool) or not .5<=policy['near_threshold']<=1:raise ValueError('Near threshold must be .5..1')
    if set(policy['time_windows'])!=set(SPLITS):raise ValueError('All split time windows are required')
    windows={}
    for split,window in policy['time_windows'].items():
        if not isinstance(window,list) or len(window)!=2:raise ValueError('Window must contain start and end')
        start,end=map(timestamp,window)
        if start>=end:raise ValueError('Invalid time window')
        windows[split]=(start,end)
    if windows['train'][1]>windows['validation'][0] or windows['validation'][1]>windows['test'][0]:raise ValueError('Policy time windows overlap or are out of order')
    ids=set()
    for row in records:
        if not isinstance(row,dict) or set(row)!=FIELDS:raise ValueError('Invalid record fields')
        if row['split'] not in SPLITS:raise ValueError('Unknown split')
        for field in ('row_id','entity_id','source_group'):
            if not isinstance(row[field],str) or not row[field].strip() or len(row[field])>120:raise ValueError('Invalid '+field)
        if row['row_id'] in ids:raise ValueError('Duplicate row_id')
        ids.add(row['row_id'])
        if not isinstance(row['text'],str) or not normalize(row['text']) or len(row['text'])>2000:raise ValueError('Text must contain 1..2000 characters')
        timestamp(row['event_at'])
    return windows

def audit(records,policy,max_findings=1000):
    windows=validate(records,policy)
    if type(max_findings) is not int or not 1<=max_findings<=1000:raise ValueError('Invalid finding limit')
    records=sorted(records,key=lambda row:row['row_id'])
    counts=Counter();findings=[]
    def record(kind,severity,rows,**details):
        counts[kind]+=1;counts[severity]+=1
        if len(findings)<max_findings:findings.append(dict(kind=kind,severity=severity,row_ids=rows,**details))
    for row in records:
        start,end=windows[row['split']]
        if not start<=timestamp(row['event_at'])<end:
            record('outside_time_window','violation',[row['row_id']],split=row['split'],event_at=row['event_at'],window=policy['time_windows'][row['split']])
    for field in policy['disjoint_fields']:
        groups=defaultdict(list)
        for row in records:groups[row[field]].append(row)
        for value,members in sorted(groups.items()):
            if len({r['split'] for r in members})>1:
                record('group_cross_split','violation',[r['row_id'] for r in members],field=field,group_value_sha256=digest(value),splits=sorted({r['split'] for r in members}))
    token_sets={r['row_id']:set(re.findall(r'\w+',normalize(r['text']))) for r in records}
    comparisons=0
    for first,second in itertools.combinations(records,2):
        if first['split']==second['split']:continue
        comparisons+=1;ids=[first['row_id'],second['row_id']]
        if normalize(first['text'])==normalize(second['text']):
            record('normalized_text_cross_split','violation',ids,splits=[first['split'],second['split']],normalized_text_sha256=digest(normalize(first['text'])))
        else:
            a,b=token_sets[first['row_id']],token_sets[second['row_id']]
            similarity=len(a&b)/len(a|b) if a|b else 0.
            if similarity>=policy['near_threshold']:
                record('near_text_cross_split','review',ids,splits=[first['split'],second['split']],token_jaccard=similarity)
    status='fail' if counts['violation'] else 'review' if counts['review'] else 'pass'
    return dict(version=VERSION,status=status,records=len(records),split_counts=dict(Counter(r['split'] for r in records)),
        counts=dict(sorted(counts.items())),findings=findings,
        findings_truncated=sum(counts[k] for k in ('violation','review'))>len(findings),
        cross_split_text_pairs_compared=comparisons,
        input_sha256=digest(records),policy_sha256=digest(policy),
        auditor_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        scope='Violations of caller-declared split policy; near-text similarity requires human review. No semantic duplicate, label correctness or general leakage guarantee.')

def main():
    p=argparse.ArgumentParser();p.add_argument('input');p.add_argument('--policy',required=True);p.add_argument('--output',required=True)
    args=p.parse_args()
    try:
        report=audit(json.loads(Path(args.input).read_text(encoding='utf-8')),json.loads(Path(args.policy).read_text(encoding='utf-8')))
        output=Path(args.output)
        if output.exists():raise ValueError('Output exists; choose a new report filename')
        output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(report,indent=2),encoding='utf-8')
        print('AUDIT STATUS:',report['status'].upper(),'REPORT:',output)
        return {'pass':0,'review':2,'fail':1}[report['status']]
    except (ValueError,KeyError,TypeError,OSError) as error:
        print('INVALID INPUT OR OUTPUT:',error,file=sys.stderr);return 3
if __name__=='__main__':raise SystemExit(main())
