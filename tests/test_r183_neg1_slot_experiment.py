"""R183-v2 runtime bootstrap keeps legacy engine bytes unchanged."""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
BOOT=ROOT/"tools"/"r183_sitecustomize.py"

class R183BootstrapTests(unittest.TestCase):
    def child(self, code, *, experiment=False, frame=True):
        with tempfile.TemporaryDirectory() as td:
            td=pathlib.Path(td)
            shutil.copyfile(BOOT,td/"sitecustomize.py")
            env=dict(os.environ)
            env["PYTHONPATH"]=os.pathsep.join(
                [str(td),str(ROOT/"core"),str(ROOT/"tests")]+
                ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else [])
            )
            if frame: env["R183_FRAME_DEBUG"]="1"
            else: env.pop("R183_FRAME_DEBUG",None)
            if experiment: env["R183_NEG1_SLOT_EXPERIMENT"]="1"
            else: env.pop("R183_NEG1_SLOT_EXPERIMENT",None)
            p=subprocess.run([sys.executable,"-c",code],cwd=ROOT,env=env,
                             text=True,capture_output=True)
            return p

    def test_driver_style_deletion_cannot_remove_frame_debug(self):
        code=r'''
import os
for k in list(os.environ):
    if k.startswith("DEVIRT_"):
        os.environ.pop(k,None)
print(os.environ.get("DEVIRT_FRAME_DEBUG"))
'''
        p=self.child(code)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(p.stdout.strip(),"1")
        self.assertIn('"frame_debug": true',p.stderr)

    def test_experiment_off_preserves_negative_read_rejection(self):
        code=r'''
from obfuscators.luraph_v15 import devirt as d
from test_entry_facts_bridge import lifter
lf=lifter();lf.stack_base=1
try:
    lf.index(d.REGFILE,-1,None)
except d.Unsupported:
    print("REJECT")
else:
    print("ALLOWED")
'''
        p=self.child(code,experiment=False)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(p.stdout.strip(),"REJECT")

    def test_experiment_on_allows_exact_neg1_read(self):
        code=r'''
from obfuscators.luraph_v15 import devirt as d
from test_entry_facts_bridge import lifter
lf=lifter();lf.stack_base=1
v=lf.index(d.REGFILE,-1,None)
print(type(v).__name__,v.n)
'''
        p=self.child(code,experiment=True)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(p.stdout.strip(),"Reg -1")
        self.assertIn('"neg1_patch_installed": true',p.stderr)

    def test_experiment_on_allows_exact_neg1_store_without_const_identity_assumption(self):
        code=r'''
from obfuscators.luraph_v15 import devirt as d
from test_entry_facts_bridge import lifter
lf=lifter();lf.stack_base=1
lf.newindex(d.REGFILE,-1,d.Const(7),None)
x=lf.out[0]
print(type(x.target).__name__,x.target.n,type(x.value).__name__,x.value.v)
'''
        p=self.child(code,experiment=True)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(p.stdout.strip(),"Reg -1 Const 7")

    def test_experiment_does_not_allow_other_negative_or_zero_slots(self):
        code=r'''
from obfuscators.luraph_v15 import devirt as d
from test_entry_facts_bridge import lifter
ok=[]
for key in (-2,0):
    lf=lifter();lf.stack_base=1
    try: lf.index(d.REGFILE,key,None)
    except d.Unsupported: ok.append(key)
print(ok)
'''
        p=self.child(code,experiment=True)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(p.stdout.strip(),"[-2, 0]")

if __name__=="__main__":
    unittest.main()
