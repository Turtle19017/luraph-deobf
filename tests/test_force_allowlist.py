"""Exercise the actual Luau request boundary without running any target."""
import pathlib
import subprocess
import tempfile
import unittest


class ForceAllowlistTests(unittest.TestCase):
    def test_exact_paths_and_receipts(self):
        repo = pathlib.Path(__file__).resolve().parents[1]
        runtime = (repo / "runtime/envlog.luau").read_text(encoding="utf-8")
        guard = runtime.split("local CHAIN = { pf = nil, pid = nil, plast = nil }", 1)[1].split("function CHAIN.get()", 1)[0]
        script = '''local CFG = {force_allowlist = {"31,b,1@2", "31,b,3@4"}}
local R = {type=type, ipairs=ipairs, error=error, gsub=string.gsub,
fmt=string.format, byte=string.byte, print=print}
local CHAIN = {}
''' + guard + '''
assert(CHAIN.allowForceRequest("31,b,1@2"))
assert(not CHAIN.allowForceRequest("31,b,1@20"))
assert(not CHAIN.allowForceRequest("31,b"))
assert(not CHAIN.allowForceRequest("!31,b,1@2"))
CHAIN.noteForceResult("31,b,1@2", true, false)
CHAIN.noteForceResult("31,b,3@4", true, nil)
CHAIN.forceAllowedPaths = nil
assert(CHAIN.allowForceRequest("legacy"))
'''
        temp = pathlib.Path(tempfile.gettempdir()) / "opencode"
        temp.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="force_guard_test_", dir=temp) as directory:
            path = pathlib.Path(directory) / "guard.luau"
            path.write_text(script, encoding="utf-8")
            result = subprocess.run([str(repo / "bin/luau.exe"), str(path)], capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(result.stdout.count(b"FORCEGUARD blocked"), 3)
        self.assertEqual(result.stdout.count(b"FORCEGUARD attempted"), 1)
        self.assertEqual(result.stdout.count(b"FORCEGUARD decoded"), 1)
        self.assertEqual(result.stdout.count(b"FORCEGUARD missing"), 1)


if __name__ == "__main__":
    unittest.main()
