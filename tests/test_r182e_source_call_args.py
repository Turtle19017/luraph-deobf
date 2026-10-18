import importlib.util,json,pathlib,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
P=ROOT/"tools"/"recover_r182e_source_call_args.py"
SPEC=importlib.util.spec_from_file_location("r182e",P)
r=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r)

def receipts():
    fi=[];gi=[]
    for i in range(136):
        call=i>=95
        rt="AstExprCall" if call else "AstExprIndexExpr"
        fid=f"F{i%7}";sid=f"S{i%7}"
        fi.append({
            "function_id":fid,"state_id":sid,"right_type":rt,
            "local_snapshot_entries":[{"name":"a","value":11},{"name":"b","value":22}],
        })
        right={"type":rt,"location":f"L{i}"}
        schema={}
        if call:
            right.update({"func":{"type":"AstExprLocal","name":"v","location":f"VF{i}"},"argc":2})
            schema={"argc":2}
        gi.append({
            "instance_index":i,"function_id":fid,"state_id":sid,"right_type":rt,
            "right_node":right,"rhs_schema":schema,
        })
    cp={"expected":{"functions":78,"errors":64,"fallbacks":0,"requests":594}}
    return (
        {"schema":"luraph-deobf.r181f-local-identity-rhs-census.v1","checkpoint":cp,"instances":fi},
        {"schema":"luraph-deobf.r181g-rhs-local-dependency-census.v1","checkpoint":cp,"instances":gi},
    )

def source_root(*,missing=None,duplicate=None,argc_bad=None,func_bad=None):
    body=[]
    for i in range(95,136):
        if i==missing: continue
        call={
            "type":"AstExprCall","location":f"L{i}",
            "func":{"type":"AstExprLocal","location":f"VF{i}",
                    "local":{"name":"other" if i==func_bad else "v","location":f"VD{i}"}},
            "args":[
                {"type":"AstExprLocal","location":f"A{i}",
                 "local":{"name":"a","location":f"AD{i}"}},
                {"type":"AstExprConstantNumber","location":f"B{i}","value":22},
            ],
        }
        if i==argc_bad:
            call["args"]=call["args"][:1]
        body.append({"type":"AstStatExpr","location":f"S{i}","expr":call})
        if i==duplicate:
            body.append({"type":"AstStatExpr","location":f"SX{i}","expr":dict(call)})
    return {"type":"AstStatBlock","location":"ROOT","body":body}

class R182ETests(unittest.TestCase):
    def test_recovers_all_41_call_argument_asts(self):
        f,g=receipts()
        rows,shapes,locs=r.recover_from_ast(f,g,source_root())
        self.assertEqual(len(rows),41)
        self.assertEqual(len(locs),41)
        self.assertEqual(rows[0]["argc"],2)
        self.assertEqual(rows[0]["args"][0]["name"],"a")
        self.assertEqual(rows[0]["args"][1]["value"],22)

    def test_missing_location_fails(self):
        f,g=receipts()
        with self.assertRaisesRegex(ValueError,"matched 0"):
            r.recover_from_ast(f,g,source_root(missing=100))

    def test_duplicate_location_fails(self):
        f,g=receipts()
        with self.assertRaisesRegex(ValueError,"matched 2"):
            r.recover_from_ast(f,g,source_root(duplicate=100))

    def test_source_argc_mismatch_fails(self):
        f,g=receipts()
        with self.assertRaisesRegex(ValueError,"argc mismatch"):
            r.recover_from_ast(f,g,source_root(argc_bad=100))

    def test_source_func_identity_mismatch_fails(self):
        f,g=receipts()
        with self.assertRaisesRegex(ValueError,"not local v"):
            r.recover_from_ast(f,g,source_root(func_bad=100))

    def test_receipt_instance_identity_mismatch_fails(self):
        f,g=receipts();g["instances"][95]["function_id"]="OTHER"
        with self.assertRaisesRegex(ValueError,"join mismatch"):
            r.recover_from_ast(f,g,source_root())

    def test_sha256_helper_is_exact(self):
        self.assertEqual(
            r.sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )

if __name__=="__main__":
    unittest.main()
