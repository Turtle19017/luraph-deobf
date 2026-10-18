import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
P = ROOT / 'tools' / 'analyze_r181a_negative_slot_structure.py'
SPEC = importlib.util.spec_from_file_location('r181a', P)
r = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r)

def fixture(root, n=19):
    sites = []
    for i in range(n):
        reg = -(i % 3 + 1)
        base = i % 3 + 1
        sites.append({
            'function_id': f'F{i}', 'state_id': f'S{i}', 'register': reg,
            'stack_base': base, 'operation': 'read' if i < 12 else 'store',
            'mode': 93, 'pc': 100 + i, 'last_op': 'OP', 'in_jump_regs': i % 2 == 0,
        })
    obj = {
        'schema': 'luraph-deobf.r179b-underflow-artifact-census.v4',
        'checkpoint': {'expected': {'functions': 78, 'errors': 64, 'fallbacks': 0, 'requests': 594}},
        'canonical_error_nodes': {'unique_composite_ids': 64},
        'sites': sites + [
            {'function_id': f'R{i}', 'state_id': f'Z{i}', 'register': 0, 'operation': 'read'}
            for i in range(30)
        ],
    }
    p = root / 'c.json'
    p.write_text(json.dumps(obj), encoding='utf-8')
    return p

class R181ATests(unittest.TestCase):
    def test_counts(self):
        with tempfile.TemporaryDirectory() as td:
            out = r.analyze(fixture(pathlib.Path(td)), 19)
            self.assertEqual(out['summary']['read'], 12)
            self.assertEqual(out['summary']['store'], 7)

    def test_affine_is_measurement_only(self):
        with tempfile.TemporaryDirectory() as td:
            out = r.analyze(fixture(pathlib.Path(td)), 19)
            self.assertEqual(out['affine_patterns']['register_plus_stack_base']['dominant']['count'], 19)
            self.assertFalse(out['interpretation_gate']['affine_pattern_proves_bug'])

    def test_missing_base(self):
        with tempfile.TemporaryDirectory() as td:
            p = fixture(pathlib.Path(td))
            obj = json.loads(p.read_text())
            obj['sites'][0]['stack_base'] = None
            p.write_text(json.dumps(obj))
            self.assertEqual(r.analyze(p, 19)['summary']['stack_base_missing'], 1)

    def test_count_gate(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaisesRegex(ValueError, 'expected 19 negative sites'):
                r.analyze(fixture(pathlib.Path(td), 18), 19)

    def test_duplicate_identity_fails(self):
        with tempfile.TemporaryDirectory() as td:
            p = fixture(pathlib.Path(td))
            obj = json.loads(p.read_text())
            obj['sites'][1]['function_id'] = obj['sites'][0]['function_id']
            obj['sites'][1]['state_id'] = obj['sites'][0]['state_id']
            p.write_text(json.dumps(obj))
            with self.assertRaisesRegex(ValueError, 'duplicate negative composite identity'):
                r.analyze(p, 19)

if __name__ == '__main__':
    unittest.main()
