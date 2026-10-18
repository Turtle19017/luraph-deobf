import importlib.util,json,pathlib,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1];P=ROOT/"tools"/"analyze_r179b_underflow_artifacts.py";sp=importlib.util.spec_from_file_location("r",P);r=importlib.util.module_from_spec(sp);sp.loader.exec_module(r)
def pairs():
 o=[]
 for i in range(49):
  op="read"if i<35 else"store";reg=0 if i<30 else-(i-29);m=93+i%2;p=100+i;o.append((f"S{i}",f"{op} below the stack VM's frame (register {reg}) (at {m}:{p})"))
 for i in range(5):o.append((f"C{i}",f"symbolic next pc/mode: r{i} / 93 (at 93:{500+i})"))
 for i in range(9):o.append((f"M{i}",f"needs a constant that is not decoded yet (at 99:{600+i})"))
 o.append(("B0","bit32.bxor failed: NoneType (at 223:700)"));return o
def base(root):
 (root/"summary.json").write_text(json.dumps({"stats":{"functions":78,"errors":64,"fallbacks":0},"requests":594,"output_sha256":"x"}),encoding="utf-8")
def graph(root,with_error=True):
 x=[{"state_id":s,**({"error":e}if with_error else{})}for s,e in pairs()];(root/"graph_error_states.json").write_text(json.dumps({"states":x}),encoding="utf-8")
class T(unittest.TestCase):
 def test_graph_identity(self):
  with tempfile.TemporaryDirectory()as td:
   q=pathlib.Path(td);base(q);graph(q);o=r.analyze([q],49);self.assertEqual(o["summary"]["unique_sites"],49);self.assertEqual(o["canonical_error_nodes"]["identity_scheme"],"graph_error_states.state_id")
 def test_263_raw_cannot_create(self):
  with tempfile.TemporaryDirectory()as td:
   q=pathlib.Path(td);base(q);graph(q);(q/"raw.jsonl").write_text("".join(json.dumps({"kind":"below_stack","register":-i-1,"state_id":f"RAW{i}"})+"\n"for i in range(263)),encoding="utf-8");o=r.analyze([q],49);self.assertEqual(o["summary"]["unique_sites"],49);self.assertEqual(o["summary"]["auxiliary_records_with_explicit_state_id"],0)
 def test_explicit_nested_adapter(self):
  with tempfile.TemporaryDirectory()as td:
   q=pathlib.Path(td);base(q);graph(q,False);(q/"resolved.json").write_text(json.dumps({"records":[{"error":e,"provenance":{"graph_state_id":s}}for s,e in pairs()]}),encoding="utf-8");o=r.analyze([q],49);self.assertTrue(all(x["provenance_join"]=="explicit_state_id_reference"for x in o["sites"]))
 def test_no_provenance_fails(self):
  with tempfile.TemporaryDirectory()as td:
   q=pathlib.Path(td);base(q);graph(q,False);(q/"backend.json").write_text(json.dumps([{"error":e}for _,e in pairs()]),encoding="utf-8")
   with self.assertRaisesRegex(ValueError,"refusing order/diagnostic-based identity synthesis"):r.analyze([q],49)
 def test_duplicate_ref_fails(self):
  with tempfile.TemporaryDirectory()as td:
   q=pathlib.Path(td);base(q);graph(q,False);x=[{"error":e,"state_id":s}for s,e in pairs()];x[1]["state_id"]="S0";(q/"resolved.json").write_text(json.dumps(x),encoding="utf-8")
   with self.assertRaisesRegex(ValueError,"refusing order/diagnostic-based identity synthesis"):r.analyze([q],49)
 def test_explicit_enrichment(self):
  with tempfile.TemporaryDirectory()as td:
   q=pathlib.Path(td);base(q);graph(q);(q/"frame.jsonl").write_text(json.dumps({"kind":"below_stack","register":0,"state_id":"S0","stack_base":7,"jump_regs":[0]})+"\n",encoding="utf-8");o=r.analyze([q],49);s=next(x for x in o["sites"]if x["state_id"]=="S0");self.assertEqual(s["stack_base"],7);self.assertTrue(s["in_jump_regs"])
if __name__=="__main__":unittest.main()
