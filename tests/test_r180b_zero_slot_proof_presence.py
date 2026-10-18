import importlib.util,json,pathlib,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1];P=ROOT/'tools'/'analyze_r180b_zero_slot_proof_presence.py';s=importlib.util.spec_from_file_location('r',P);r=importlib.util.module_from_spec(s);s.loader.exec_module(r)
def c(root):
 o={'schema':'luraph-deobf.r179b-underflow-artifact-census.v4','checkpoint':{'expected':{'functions':78,'errors':64,'fallbacks':0,'requests':594}},'sites':[{'function_id':f'F{i}','state_id':f'S{i}','register':0} for i in range(30)]};p=root/'c.json';p.write_text(json.dumps(o));return p
class T(unittest.TestCase):
 def test_absent(self):
  with tempfile.TemporaryDirectory() as td:
   q=pathlib.Path(td);cp=c(q);e=q/'e.log';e.write_text('old artifact');self.assertEqual(r.analyze(cp,[e])['summary']['NO_PROOF_AVAILABLE'],30)
 def test_marker_fails(self):
  with tempfile.TemporaryDirectory() as td:
   q=pathlib.Path(td);cp=c(q);e=q/'e.log';e.write_text('frame_entry_fact_source_0');
   with self.assertRaisesRegex(ValueError,'markers exist'):r.analyze(cp,[e])
 def test_bad_checkpoint_fails(self):
  with tempfile.TemporaryDirectory() as td:
   q=pathlib.Path(td);cp=c(q);o=json.loads(cp.read_text());o['checkpoint']['expected']['requests']=593;cp.write_text(json.dumps(o));e=q/'e';e.mkdir()
   with self.assertRaisesRegex(ValueError,'checkpoint'):r.analyze(cp,[e])
if __name__=='__main__':unittest.main()
