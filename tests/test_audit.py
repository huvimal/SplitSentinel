import copy,json,tempfile,unittest
from pathlib import Path
from audit import audit,normalize
from fixtures import clean,contaminated,near_only,POLICY
from snapshot import freeze,verify

class AuditTests(unittest.TestCase):
    def test_clean_policy_passes(self):self.assertEqual(audit(clean(),POLICY)['status'],'pass')
    def test_all_authored_contamination_categories(self):
        r=audit(contaminated(),POLICY)
        self.assertEqual(r['status'],'fail')
        for key in ('group_cross_split','normalized_text_cross_split','outside_time_window','near_text_cross_split'):self.assertGreater(r['counts'][key],0)
        self.assertTrue(any(f['row_ids']==['test-01','train-01'] for f in r['findings']))
    def test_unicode_case_and_whitespace_normalization(self):
        self.assertEqual(normalize(' ＡＢＣ  test\n'),normalize('abc TEST'))
        rows=clean();rows[-1]['text']='  '+rows[0]['text'].upper()+'\n'
        self.assertGreater(audit(rows,POLICY)['counts']['normalized_text_cross_split'],0)
    def test_near_duplicate_requires_review(self):self.assertEqual(audit(near_only(),POLICY)['status'],'review')
    def test_same_split_repetition_not_cross_split_leak(self):
        rows=clean();rows[1]['text']=rows[0]['text'];rows[1]['entity_id']=rows[0]['entity_id']
        self.assertEqual(audit(rows,POLICY)['status'],'pass')
    def test_group_policy_is_explicit(self):
        rows=clean();rows[-1]['entity_id']=rows[0]['entity_id']
        self.assertEqual(audit(rows,POLICY)['status'],'fail')
        policy=copy.deepcopy(POLICY);policy['disjoint_fields']=[]
        self.assertEqual(audit(rows,policy)['status'],'pass')
    def test_windows_are_start_inclusive_end_exclusive(self):
        rows=clean();rows[0]['event_at']=POLICY['time_windows']['train'][0]
        self.assertEqual(audit(rows,POLICY)['status'],'pass')
        rows[0]['event_at']=POLICY['time_windows']['train'][1]
        self.assertEqual(audit(rows,POLICY)['counts']['outside_time_window'],1)
    def test_invalid_time_and_duplicate_id_fail_closed(self):
        rows=clean();rows[0]['event_at']='2025-01-01T00:00:00'
        with self.assertRaises(ValueError):audit(rows,POLICY)
        rows=clean();rows[1]['row_id']=rows[0]['row_id']
        with self.assertRaises(ValueError):audit(rows,POLICY)
    def test_policy_window_overlap_and_boolean_version_rejected(self):
        p=copy.deepcopy(POLICY);p['time_windows']['train'][1]='2025-02-02T00:00:00Z'
        with self.assertRaises(ValueError):audit(clean(),p)
        p=copy.deepcopy(POLICY);p['version']=True
        with self.assertRaises(ValueError):audit(clean(),p)
    def test_input_order_and_truncated_findings(self):
        self.assertEqual(audit(clean(),POLICY),audit(clean()[::-1],POLICY))
        r=audit(contaminated(),POLICY,max_findings=1)
        self.assertTrue(r['findings_truncated']);self.assertEqual(len(r['findings']),1);self.assertEqual(r['status'],'fail')
    def test_snapshot_reconstruction_and_tamper_detection(self):
        with tempfile.TemporaryDirectory() as td:
            p=freeze(contaminated(),POLICY,Path(td))
            self.assertTrue(verify(p)['logical_report_matches'])
            self.assertEqual(p,freeze(contaminated()[::-1],POLICY,Path(td)))
            (p/'input.json').write_text('[]')
            with self.assertRaises(ValueError):verify(p)
    def test_unknown_fields_and_bounds_rejected(self):
        rows=clean();rows[0]['label']=1
        with self.assertRaises(ValueError):audit(rows,POLICY)
        with self.assertRaises(ValueError):audit([],POLICY)

if __name__=='__main__':unittest.main()
