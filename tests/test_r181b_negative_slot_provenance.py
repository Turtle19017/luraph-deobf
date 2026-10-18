import importlib.util,json,pathlib,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1];P=ROOT/'tools'/'analyze_r181b_negative_slot_provenance.py';sp=importlib.util.spec_from_file_location('r',P);r=importlib.util.module_from_spec(sp);sp.loader.exec_module(r)
def structure(root):
 sites=[]
 for i in range(19):
  reg=-1 if i<9 else -(50+i);base=1 if i<9 else 2
  sites.append({'function_id':f'F{i}','state_id':f'S{i}','register':reg,'stack_base':base,'operation':'read' if i<14 else 'store','last_op':'OP'})
 o={'schema':'luraph-deobf.r181a-negative-slot-structural-census.v1','checkpoint':{'expected':{'functions':78,'errors':64,'fallbacks':0,'requests':594}},'sites':sites}
 p=root/'s.json';p.write_text(json.dumps(o));return p
class T(unittest.TestCase):
 def test_cohort(self):
  with tempfile.TemporaryDirectory() as td:
   q=pathlib.Path(td);s=structure(q);e=q/'e';e.mkdir();o=r.analyze(s,[e],9);self.assertEqual(o['cohort_invariant'],{'register':-1,'stack_base':1})
 def test_exact_composite_raw_key(self):
  with tempfile.TemporaryDirectory() as td:
   q=pathlib.Path(td);s=structure(q);e=q/'e.jsonl';e.write_text(json.dumps({'kind':'below_stack','register':-1,'function_id':'F0','state_id':'S0','raw_key':-1,'raw_key_type':'int','producer':{'x':1}})+'\n');o=r.analyze(s,[e],9);self.assertEqual(o['summary']['RAW_KEY_OBSERVED'],1);self.assertEqual(o['summary']['raw_key_exact_minus_one'],1)
 def test_wrong_function_same_state_ignored(self):
  with tempfile.TemporaryDirectory() as td:
   q=pathlib.Path(td);s=structure(q);e=q/'e.jsonl';e.write_text(json.dumps({'kind':'below_stack','register':-1,'function_id':'OTHER','state_id':'S0','raw_key':-1})+'\n');o=r.analyze(s,[e],9);self.assertEqual(o['summary']['NO_EXPLICIT_MATCH'],9)
 def test_unrelated_same_state_ignored(self):
  with tempfile.TemporaryDirectory() as td:
   q=pathlib.Path(td);s=structure(q);e=q/'e.json';e.write_text(json.dumps({'function_id':'F0','state_id':'S0','kind':'other','raw_key':-1}));o=r.analyze(s,[e],9);self.assertEqual(o['summary']['NO_EXPLICIT_MATCH'],9)
 def test_gate(self):
  with tempfile.TemporaryDirectory() as td:
   q=pathlib.Path(td);s=structure(q);e=q/'e';e.mkdir()
   with self.assertRaisesRegex(ValueError,'expected 8 unique'):r.analyze(s,[e],8)
if __name__=='__main__':unittest.main()
