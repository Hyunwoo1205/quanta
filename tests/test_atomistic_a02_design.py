"""Meaningful tamper checks for the inactive scientific lock, not solver tests."""
import importlib.util
import json
from pathlib import Path
import shutil

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def lock_copy(tmp_path):
    script = ROOT/'scripts/check_atomistic_a02.py'
    spec = importlib.util.spec_from_file_location('a02_check_for_test', script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    rel = Path('docs/design/atomistic-a02-v0.1')
    shutil.copytree(ROOT/rel, tmp_path/rel)
    (tmp_path/'scripts').mkdir()
    shutil.copyfile(script, tmp_path/'scripts/check_atomistic_a02.py')
    module.ROOT, module.D = tmp_path, tmp_path/rel
    return module


def replace_and_rehash(module, relative, transform):
    p = module.D/relative
    p.write_text(transform(p.read_text()))
    manifest = module.read(module.D/'manifest.json')
    entry = next(x for x in manifest['files'] if x['path']==str(p.relative_to(module.ROOT)))
    entry.update(module.identity(p))
    (module.D/'manifest.json').write_text(json.dumps(manifest))


def test_lock_is_metadata_only(lock_copy):
    report = lock_copy.verify()
    assert report['passed'] and len(report['basis'])==3
    assert not report['engine_executed'] and not report['container_layers_pulled']


def test_changed_coefficient_rejected_even_with_new_checksum(lock_copy):
    replace_and_rehash(lock_copy,'assets/cc-pVTZ.cp2k',lambda s:s.replace('3.387000E+01','3.388000E+01',1))
    with pytest.raises(AssertionError):
        lock_copy.verify()


def test_wrong_architecture_rejected_even_with_new_checksum(lock_copy):
    def change(s):
        d=json.loads(s);d['architecture_images'][0]['platform']='linux/amd64';return json.dumps(d)
    replace_and_rehash(lock_copy,'engine-lock.json',change)
    with pytest.raises(AssertionError):
        lock_copy.verify()


def test_fixture_menu_policy_cannot_replace_user_authoring(lock_copy):
    def change(s):
        d=json.loads(s);d['fixture_id_as_execution_selector']=True;return json.dumps(d)
    replace_and_rehash(lock_copy,'authoring-requirements.json',change)
    with pytest.raises(AssertionError):
        lock_copy.verify()


def test_missing_license_cannot_be_hidden_by_manifest(lock_copy):
    path=lock_copy.D/'licenses/BSE-BSD-3-Clause.txt'
    manifest=lock_copy.read(lock_copy.D/'manifest.json')
    manifest['files']=[x for x in manifest['files'] if x['path']!=str(path.relative_to(lock_copy.ROOT))]
    path.unlink();(lock_copy.D/'manifest.json').write_text(json.dumps(manifest))
    with pytest.raises(AssertionError):
        lock_copy.verify()
