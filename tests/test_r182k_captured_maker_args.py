import hashlib,importlib.util,json,pathlib,tempfile,types,unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[1]
P=ROOT/"tools"/"analyze_r182k_captured_maker_args.py"
SPEC=importlib.util.spec_from_file_location("r182k",P)
r=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(r)

class Builtin:
    def __init__(self,name):self.name=name
    def __repr__(self):return f"Builtin({self.name})"

class LTable:
    def __init__(self,tid=None,h=None):self.tid=tid;self.h=dict(h or {})
    def __repr__(self):return f"LTable#{self.tid}"

class OpaqueFn:
    def __init__(self,lfid,pf_tid=None):self.lfid=lfid;self.pf_tid=pf_tid;self.node=None

class S:
    Builtin=Builtin;LTable=LTable
    @staticmethod
    def norm_key(k):return k

D=types.SimpleNamespace(S=S,OpaqueFn=OpaqueFn)

class VM:
    def __init__(self,tag,proto,vmobj,maker_loc="MAKER"):
        self.tag=tag;self._proto=proto;self._vmobj=vmobj;self.maker={"location":maker_loc}
    def proto_of(self,cap):return self._proto
    def vmobj_of(self,cap):return self._vmobj

class Dump:
    def __init__(self,caps,pid=None,late=None):
        self.protos=caps;self.pid_of_table=pid or {};self.late=set(late or ())

class Prog:
    def __init__(self,dump,cap_to_vm):
        self.dump=dump;self._m=cap_to_vm
    def vm_of(self,cap):return self._m[id(cap)]

def write_json(p,obj):
    p.write_text(json.dumps(obj),encoding="utf-8");return p

def cp():return {"expected":{"functions":78,"errors":64,"fallbacks":0,"requests":594}}

def fixtures(q, *, wrong_role=False, bad_protos_sha=False):
    source=q/"script.txt";source.write_bytes(b"synthetic-source")
    source_sha=hashlib.sha256(source.read_bytes()).hexdigest()
    protos=q/"x.protos.json";protos.write_text(json.dumps({"tables":{},"protos":{},"pid_of_table":{}}),encoding="utf-8")
    psha=hashlib.sha256(protos.read_bytes()).hexdigest()
    if bad_protos_sha:psha="0"*64
    c=write_json(q/"c.json",{
        "schema":"luraph-deobf.r182c-base-sub-consistency.v1","checkpoint":cp(),
        "selected_base_snapshot":{"path":str(protos),"sha256":psha},
    })
    i=write_json(q/"i.json",{
        "schema":"luraph-deobf.r182i-static-path-resolution.v1","checkpoint":cp(),
        "roots":[
            {"name":"r","resolution":{"reason":"INDEX_BASE_UNRESOLVED","root_name":"B","root_decl":"DB","index_path":[124]}},
            {"name":"K","resolution":{"reason":"INDEX_BASE_UNRESOLVED","root_name":"c","root_decl":"Dc","index_path":[10]}},
            {"name":"h","resolution":{"reason":"INDEX_BASE_UNRESOLVED","root_name":"c","root_decl":"Dc","index_path":[11]}},
        ],
    })
    B_role="OTHER" if wrong_role else "VMOBJ"
    j=write_json(q/"j.json",{
        "schema":"luraph-deobf.r182j-parameter-provenance-census.v2","checkpoint":cp(),
        "parameters":[
            {"name":"B","maker_role":{"role":B_role,"param_index":0,
                "maker_function_location":"MAKER","proto_index":3,"upvals_index":2}},
            {"name":"c","maker_role":{"role":"PROTO","param_index":3,
                "maker_function_location":"MAKER","proto_index":3,"upvals_index":2}},
        ],
    })
    inst=[]
    for n in range(41):
        inst.append({"instance_index":95+n,"function_id":"57",
                     "state_id":"S1" if n<20 else "S2"})
    e=write_json(q/"e.json",{
        "schema":"luraph-deobf.r182e-source-call-arg-recovery.v2","checkpoint":cp(),
        "instances":inst,
    })
    ev=q/"ev.jsonl"
    ev.write_text("\n".join([
        json.dumps({"function_id":"57","state_id":"S1","proto_tid":900,"vm_tag":"TAG"}),
        json.dumps({"function_id":"57","state_id":"S2","proto_tid":900,"vm_tag":"TAG"}),
    ])+"\n",encoding="utf-8")
    return c,i,j,e,source,source_sha,ev

def fake_program(*,ambiguous=False,late=None,second_tag="TAG"):
    t369=LTable(369,{356:4})
    t500=LTable(500,{356:3})
    proto=LTable(900,{10:t369,11:t500})
    vmobj=LTable(800,{124:Builtin("bit32.rshift")})
    cap1={"cap":1};vm1=VM("TAG",proto,vmobj)
    caps={"57":cap1};m={id(cap1):vm1}
    if ambiguous:
        cap2={"cap":2};vm2=VM(second_tag,proto,vmobj)
        caps["58"]=cap2;m[id(cap2)]=vm2
    return Prog(Dump(caps,{900:57},late=late),m),D

class R182KTests(unittest.TestCase):
    def run_case(self,q,prog=None,**fx):
        c,i,j,e,source,sha,ev=fixtures(q,**fx)
        if prog is None:prog=fake_program()
        with mock.patch.object(r,"build_program",return_value=prog):
            return r.analyze(c,i,j,e,source,[ev],sha)

    def test_unique_capture_join_resolves_vmobj_and_proto_paths(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);out=self.run_case(q)
            self.assertEqual(out["summary"]["states_with_unique_capture_join"],2)
            self.assertEqual(out["summary"]["unique_capture_values"],1)
            cap=out["captures"][0]
            self.assertEqual(cap["roots"]["r"]["result"]["value"]["name"],"bit32.rshift")
            self.assertEqual(cap["roots"]["K"]["result"]["value"]["tid"],369)
            self.assertEqual(cap["roots"]["h"]["result"]["value"]["tid"],500)

    def test_nested_other_state_metadata_does_not_contaminate(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td)
            c,i,j,e,source,sha,ev=fixtures(q)
            ev.write_text(json.dumps({
                "function_id":"57","state_id":"S1","proto_tid":900,"vm_tag":"TAG",
                "nested":{"function_id":"99","state_id":"OTHER","proto_tid":999,"vm_tag":"BAD"}
            })+"\n"+json.dumps({
                "function_id":"57","state_id":"S2","proto_tid":900,"vm_tag":"TAG"
            })+"\n",encoding="utf-8")
            with mock.patch.object(r,"build_program",return_value=fake_program()):
                out=r.analyze(c,i,j,e,source,[ev],sha)
            self.assertEqual(out["summary"]["states_with_unique_capture_join"],2)
            self.assertEqual({x["proto_tid"] for x in out["states"]},{900})

    def test_vm_tag_disambiguates_same_proto_capture(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td)
            out=self.run_case(q,prog=fake_program(ambiguous=True,second_tag="OTHER"))
            self.assertEqual(out["summary"]["states_with_unique_capture_join"],2)
            self.assertEqual(out["captures"][0]["vm_tag"],"TAG")

    def test_same_vm_tag_duplicate_capture_stays_ambiguous(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td)
            out=self.run_case(q,prog=fake_program(ambiguous=True,second_tag="TAG"))
            self.assertEqual(out["summary"]["states_with_unique_capture_join"],0)
            self.assertTrue(all(x["classification"]=="AMBIGUOUS_CAPTURE_JOIN" for x in out["states"]))
            self.assertEqual(out["captures"],[])

    def test_late_proto_path_is_not_promoted(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td)
            out=self.run_case(q,prog=fake_program(late={(900,10)}))
            row=out["captures"][0]["roots"]["K"]["result"]
            self.assertEqual(row["status"],"UNRESOLVED")
            self.assertEqual(row["reason"],"CAPTURED_PATH_KEY_IS_LATE")

    def test_wrong_maker_role_fails(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td)
            with self.assertRaisesRegex(ValueError,"unexpected maker roles"):
                self.run_case(q,wrong_role=True)

    def test_selected_protos_sha_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td)
            with self.assertRaisesRegex(ValueError,"selected protos SHA mismatch"):
                self.run_case(q,bad_protos_sha=True)

if __name__=="__main__":
    unittest.main()
