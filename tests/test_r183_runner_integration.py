import importlib.util,json,os,pathlib,tempfile,unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[1]
P=ROOT/"tools"/"run_r183_breakthrough.py"
SPEC=importlib.util.spec_from_file_location("r183run",P)
r=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(r)

class R183RunnerIntegrationTests(unittest.TestCase):
    def test_probe_discovery_handles_repo_nested_beside_workspace_probe(self):
        with tempfile.TemporaryDirectory() as td:
            base=pathlib.Path(td)
            repo=base/"_ext"/"repo";repo.mkdir(parents=True)
            probe=base/"_probe";probe.mkdir()
            (probe/"attribute_root27_frontier78.py").write_text("# driver\n",encoding="utf-8")
            old=os.getcwd()
            try:
                os.chdir(repo)
                got=r.discover_probe(None,repo)
            finally:
                os.chdir(old)
            self.assertEqual(got,probe.resolve())

    def test_baseline_discovery_requires_exact_checkpoint_and_hashes(self):
        with tempfile.TemporaryDirectory() as td:
            probe=pathlib.Path(td)
            good={"stats":{"functions":78,"errors":64,"fallbacks":0},"requests":594,
                  "source_sha256":r.SOURCE_SHA,"output_sha256":r.OUTPUT_SHA}
            bad=dict(good);bad["requests"]=593
            (probe/"summary.bad.json").write_text(json.dumps(bad),encoding="utf-8")
            d=probe/"v15_root27_frontier78_attribution_bigstack";d.mkdir()
            goodp=d/"summary.json";goodp.write_text(json.dumps(good),encoding="utf-8")
            picked,hits=r.discover_baseline(None,probe)
            self.assertEqual(picked,goodp.resolve())
            self.assertEqual(hits,[goodp.resolve()])

    def test_baseline_discovery_skips_non_dict_stats(self):
        with tempfile.TemporaryDirectory() as td:
            probe=pathlib.Path(td)
            for i,stats in enumerate(([78,64,0],"78/64/0",None)):
                obj={"stats":stats,"requests":594,
                     "source_sha256":r.SOURCE_SHA,"output_sha256":r.OUTPUT_SHA}
                (probe/f"summary.malformed.{i}.json").write_text(json.dumps(obj),encoding="utf-8")
                self.assertFalse(r.accepted_summary(probe/f"summary.malformed.{i}.json"))
            good={"stats":{"functions":78,"errors":64,"fallbacks":0},"requests":594,
                  "source_sha256":r.SOURCE_SHA,"output_sha256":r.OUTPUT_SHA}
            goodp=probe/"summary.good.json";goodp.write_text(json.dumps(good),encoding="utf-8")
            picked,hits=r.discover_baseline(None,probe)
            self.assertEqual(picked,goodp.resolve())
            self.assertEqual(hits,[goodp.resolve()])

    def test_selected_protos_falls_back_from_stale_receipt_path_to_probe_hash_match(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);probe=q/"_probe";probe.mkdir()
            target=probe/"snap"/"decoded.protos.json";target.parent.mkdir()
            target.write_text("{}",encoding="utf-8")
            c=q/"r182c.json"
            c.write_text(json.dumps({"selected_base_snapshot":{
                "path":"Z:/stale/decoded.protos.json","sha256":r.PROTO_SHA}}),encoding="utf-8")
            with mock.patch.object(r,"sha256_file",side_effect=lambda p: r.PROTO_SHA if pathlib.Path(p).resolve()==target.resolve() else "x"):
                got=r.resolve_selected_protos(c,probe)
            self.assertEqual(got,target.resolve())

    def test_find_source_prefers_workspace_accepted_hash(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);repo=q/"_ext"/"repo";repo.mkdir(parents=True)
            workspace=q;src=workspace/"script.txt";src.write_text("x",encoding="utf-8")
            with mock.patch.object(r,"sha256_file",return_value=r.SOURCE_SHA):
                got=r.find_source(None,workspace,repo)
            self.assertEqual(got,src.resolve())

    def test_reused_capture_log_requires_baseline_boot_marker(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td)
            good=q/"good.log"
            good.write_text('[R183BOOT] {"frame_debug": true, "neg1_experiment": false}\n',encoding="utf-8")
            boot=r.reused_capture_boot(good)
            self.assertTrue(boot["frame_debug"])
            self.assertFalse(boot["neg1_experiment"])

            bad=q/"bad.log"
            bad.write_text('[R183BOOT] {"frame_debug": true, "neg1_experiment": true}\n',encoding="utf-8")
            with self.assertRaisesRegex(ValueError,"experiment log"):
                r.reused_capture_boot(bad)

    def test_reused_capture_log_without_boot_marker_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            p=pathlib.Path(td)/"capture.log"
            p.write_text("partial capture without bootstrap marker\n",encoding="utf-8")
            with self.assertRaisesRegex(ValueError,"frame-debug marker"):
                r.reused_capture_boot(p)

    def test_run_driver_stats_capture_installs_stats_patch(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);probe=q/"_probe";probe.mkdir()
            driver=probe/"driver.py"
            driver.write_text("print('ok')\n",encoding="utf-8")
            log=probe/"stats.log"
            code,boot=r.run_driver(driver,q,ROOT,probe,"label",log,True,stats_capture=True)
            self.assertEqual(code,0)
            self.assertTrue(boot["neg1_experiment"])
            self.assertTrue(boot["neg1_patch_installed"])
            self.assertTrue(boot["stats_capture"])
            self.assertTrue(boot["stats_patch_installed"])

    def test_run_driver_bootstrap_survives_legacy_devirt_cleanup(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);probe=q/"_probe";probe.mkdir()
            driver=probe/"driver.py"
            driver.write_text(
                "import os\n"
                "for k in list(os.environ):\n"
                "    if k.startswith('DEVIRT_'): os.environ.pop(k,None)\n"
                "print('FRAME=' + str(os.environ.get('DEVIRT_FRAME_DEBUG')))\n",
                encoding="utf-8")
            log=probe/"run.log"
            code,boot=r.run_driver(driver,q,ROOT,probe,"label",log,False)
            self.assertEqual(code,0)
            self.assertTrue(boot["frame_debug"])
            self.assertIn("FRAME=1",log.read_text(encoding="utf-8"))

if __name__=="__main__":
    unittest.main()
