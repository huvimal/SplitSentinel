"""Original synthetic split-policy examples; not an independent benchmark."""
from copy import deepcopy
from datetime import datetime,timedelta,timezone

POLICY=dict(version=1,disjoint_fields=['entity_id','source_group'],near_threshold=.85,
    time_windows={'train':['2025-01-01T00:00:00Z','2025-02-01T00:00:00Z'],
                  'validation':['2025-02-01T00:00:00Z','2025-03-01T00:00:00Z'],
                  'test':['2025-03-01T00:00:00Z','2025-04-01T00:00:00Z']})

def clean():
    rows=[]
    for split,n,month,base in [('train',40,1,0),('validation',20,2,1000),('test',30,3,2000)]:
        for index in range(n):
            code=base+index;identifier=f'{split}-{index:02d}'
            rows.append(dict(row_id=identifier,split=split,entity_id=f'entity-{code}',source_group=f'source-{code}',
                event_at=(datetime(2025,month,1,tzinfo=timezone.utc)+timedelta(hours=index)).isoformat(),
                text=f'Account sample {split}-{index:02d} includes distinct token z{code:04d} and the agent resolved network request number {code:04d}.'))
    return rows

def contaminated():
    rows=clean();lookup={r['row_id']:r for r in rows}
    lookup['test-00']['text']='  '+lookup['train-00']['text'].upper()+'  '
    lookup['test-01']['entity_id']=lookup['train-01']['entity_id']
    lookup['test-02']['source_group']=lookup['train-02']['source_group']
    lookup['test-03']['event_at']='2025-01-05T12:00:00Z'
    lookup['test-04']['text']=lookup['train-04']['text'].replace('resolved','fixed')
    lookup['test-05']['text']=lookup['validation-00']['text']
    return rows

def near_only():
    rows=clean();rows[-1]['text']=rows[0]['text'].replace('resolved','fixed')
    return rows
