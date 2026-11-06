"""Offline A02 source/data/image-metadata checks; does not run CP2K."""
from __future__ import annotations
import argparse
from collections import Counter
from decimal import Decimal
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
D = ROOT / 'docs/design/atomistic-a02-v0.1'


def unique(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError('duplicate JSON key')
        d[k] = v
    return d


def read(p):
    return json.loads(p.read_text(), object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def identity(p):
    b = p.read_bytes()
    return {'size_bytes': len(b), 'sha256': hashlib.sha256(b).hexdigest(),
            'git_blob_sha1': hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}


def source_shells(element):
    rows = Counter()
    for shell in element['electron_shells']:
        assert len(shell['angular_momentum']) == 1
        l = shell['angular_momentum'][0]
        exponents = tuple(map(Decimal, shell['exponents']))
        for vector in shell['coefficients']:
            rows[(l, exponents, tuple(map(Decimal, vector)))] += 1
    return rows


def parse_cp2k_basis(path):
    lines = [s.strip() for s in path.read_text().splitlines() if s.strip() and not s.lstrip().startswith('#')]
    i, elements = 0, {}
    while i < len(lines):
        element, name = lines[i].split(); n = int(lines[i+1]); i += 2
        assert element not in elements
        rows = Counter()
        for _ in range(n):
            spec = list(map(int, lines[i].split())); i += 1
            _, lo, hi, nprim, *counts = spec
            assert len(counts) == hi-lo+1
            block = [list(map(Decimal, lines[i+j].split())) for j in range(nprim)]; i += nprim
            assert all(len(r) == 1+sum(counts) and r[0] > 0 for r in block)
            exponents = tuple(r[0] for r in block); col = 1
            for l, nc in zip(range(lo, hi+1), counts):
                for _ in range(nc):
                    rows[(l, exponents, tuple(r[col] for r in block))] += 1; col += 1
        elements[element] = (name, rows)
    return elements


def verify(source_archive=None, source_root=None, bse_source_dir=None):
    manifest = read(D/'manifest.json'); paths = [f['path'] for f in manifest['files']]
    actual = {str(p.relative_to(ROOT)) for p in D.rglob('*') if p.is_file() and p.name != 'manifest.json'}
    actual.add('scripts/check_atomistic_a02.py')
    required = {'README.md', 'engine-lock.json', 'source-evidence.json',
                'density-and-units.json', 'authoring-requirements.json',
                'basis-source-selection.json', 'assets/ALL_POTENTIALS',
                'licenses/CP2K-GPL-2.0.txt', 'licenses/BSE-BSD-3-Clause.txt'}
    for name in ('cc-pVDZ', 'cc-pVTZ', 'cc-pVQZ'):
        required.update({f'assets/{name}.cp2k', f'basis-json/{name}.json', f'references/{name}.json'})
    for arch in ('arm64', 'amd64'):
        required.update({f'images/{arch}.manifest.json', f'images/{arch}.config.json'})
    required = {str((D/n).relative_to(ROOT)) for n in required} | {'scripts/check_atomistic_a02.py'}
    assert actual == required
    assert set(paths) == actual and len(paths) == len(set(paths))
    for f in manifest['files']:
        p = (ROOT/f['path']).resolve()
        assert p.is_relative_to(ROOT) and '..' not in Path(f['path']).parts
        assert identity(p) == {k:f[k] for k in ('size_bytes','sha256','git_blob_sha1')}, f['path']
    lock = read(D/'engine-lock.json'); evidence = read(D/'source-evidence.json')
    density = read(D/'density-and-units.json'); authoring = read(D/'authoring-requirements.json')
    selected = read(D/'basis-source-selection.json')
    assert lock['executable'] is False and lock['science_state']['engine_executed'] is False
    assert lock['science_state']['physical_validation_status'] == 'unvalidated'
    assert lock['source_commit'] == evidence['commit'] == density['source_commit']
    assert evidence['tag']=='v2026.2' and len(evidence['commit'])==40
    basis_results = []
    for b in lock['basis']:
        raw = read(D/b['json_file']); canonical = selected['bases'][b['name']]
        parsed = parse_cp2k_basis(D/b['file'])
        assert set(parsed)=={'H','He'} and set(raw['elements'])=={'1','2'}
        assert raw['name']==b['name'] and raw['version']=='1'
        counts = {}
        for symbol,z in [('H','1'),('He','2')]:
            assert raw['elements'][z]['electron_shells']==canonical['elements'][z]['electron_shells']
            name,rows=parsed[symbol]
            assert name==b['name'] and rows==source_shells(canonical['elements'][z])
            counts[symbol]=sum((2*key[0]+1)*n for key,n in rows.items())
        assert set(counts.values())=={{'cc-pVDZ':5,'cc-pVTZ':14,'cc-pVQZ':30}[b['name']]}
        if bse_source_dir:
            original=Path(bse_source_dir)/('coefficients-'+b['name']+'.json')
            assert identity(original)==canonical['source_identity']
            data=read(original)
            assert all(data['elements'][z]==canonical['elements'][z] for z in ['1','2'])
        basis_results.append({'name':b['name'],'elements':list(counts),'spherical_functions_per_atom':counts,'coefficients_match_fixed_source_and_api':True})
    assert len(basis_results)==3
    potentials=(D/'assets/ALL_POTENTIALS').read_text()
    assert 'H ALLELECTRON ALL' in potentials and 'He ALLELECTRON ALL' in potentials
    image_results=[]
    for image in lock['architecture_images']:
        mpath=D/image['manifest_file']; config=D/image['config_file']
        assert 'sha256:'+identity(mpath)['sha256']==image['digest']
        m=read(mpath);c=read(config)
        assert 'sha256:'+identity(config)['sha256']==m['config']['digest']==image['config_digest']
        assert identity(config)['size_bytes']==m['config']['size']
        assert image['platform']=='linux/'+c['architecture'] and c['os']=='linux'
        assert image['immutable_reference'].endswith('@'+image['digest'])
        assert sum(l['size'] for l in m['layers'])==image['compressed_layer_bytes']
        assert image['runtime_executed'] is False and image['layers_downloaded'] is False
        assert image['source_revision_attested'] is False
        image_results.append({'platform':image['platform'],'digest':image['digest'],'manifest_and_config_verified':True,'layers_and_runtime_verified':False})
    assert {i['platform'] for i in image_results}=={'linux/arm64','linux/amd64'}
    settings=density['candidate_settings']
    assert settings['DENSITY_INCLUDE']=='TOTAL_DENSITY' and settings['STRIDE']==[1,1,1]
    assert settings['XRD_INTERFACE'] is False and settings['APPEND'] is False
    assert density['engine_unit_profile']['codata_edition']==2006
    assert density['reference_constants_policy']['A01_codata_2022_references_unchanged'] is True
    assert density['cube_serialization']['not_binary64_lossless'] is True
    assert authoring['fixture_id_as_execution_selector'] is False
    assert authoring['reference_compositions_as_runtime_menu'] is False
    assert authoring['json_and_visual_editor_same_definition'] is True
    archive_checked=False
    if source_archive:
        got=identity(Path(source_archive)); wanted=evidence['source_archive']
        assert all(got[k]==wanted[k] for k in ('sha256','size_bytes'));archive_checked=True
    source_files=0
    if source_root:
        for f in evidence['files']:
            assert identity(Path(source_root)/f['path'])=={k:f[k] for k in ('size_bytes','sha256','git_blob_sha1')}
            assert evidence['commit'] in f['url']
            source_files+=1
        source=(Path(source_root)/'src/qs_scf_post_gpw.F').read_text()
        assert 'TOTAL_ELECTRON_DENSITY' in source and 'calculate_rhotot_elec_gspace' in source
        constants=(Path(source_root)/'src/common/physcon.F').read_text()
        assert 'CP2K uses the CODATA from 2006' in constants and '0.52917720859E-10' in constants
    return {'verification_kind':'A02_source_data_and_image_metadata','checked_on':'2026-11-07','passed':True,
            'locked_files_checked':len(paths),'source_archive_bytes_verified':archive_checked,
            'source_files_checked':source_files,'basis_full_source_files_checked':3 if bse_source_dir else 0,
            'basis':basis_results,'images':image_results,'authoring_requirements_checked':True,
            'engine_installed':False,'engine_executed':False,'container_layers_pulled':False,
            'image_release_source_identity_attested':False,'physical_validation_status':'unvalidated',
            'scientific_results':None,'manifest_sha256':identity(D/'manifest.json')['sha256']}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-archive',type=Path);p.add_argument('--source-root',type=Path)
    p.add_argument('--bse-source-dir',type=Path);p.add_argument('--output',type=Path)
    a=p.parse_args();result=verify(a.source_archive,a.source_root,a.bse_source_dir)
    text=json.dumps(result,ensure_ascii=False,indent=2)+'\n'
    if a.output:a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(text)
    print(text,end='')
