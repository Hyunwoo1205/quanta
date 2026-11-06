"""Fixed application gate/PPK transport; synthetic values and no remote actions."""
from __future__ import annotations

from copy import deepcopy
import base64
import importlib.util
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location('test_application_' + name, ROOT/'deploy/oci'/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = load('authorize_application_upgrade')
transport = load('probe_application_upgrade')
CONTROL = 'b'*40
REQUEST_ID = '6265bde1-e559-45b3-87c2-14a41fd3251d'


def request(operation='upgrade-application'):
    return {'schema_version':1,'operation':operation,'source_sha':gate.APP_SOURCE,'request_id':REQUEST_ID}


def environment():
    return {'GITHUB_REPOSITORY':gate.REPOSITORY,'GITHUB_REF':'refs/heads/ops/oci','GITHUB_EVENT_NAME':'push',
            'QUANTA_APPLICATION_CONTROL_SHA':CONTROL,'QUANTA_APPLICATION_CONTROL_CI_RUN':'123',
            'QUANTA_CI_READ_TOKEN':'synthetic-token'}


def run_metadata(sha,workflow,run_id):
    return {'id':run_id,'head_sha':sha,'head_branch':'main','event':'push','path':workflow,
            'status':'completed','conclusion':'success'}


def job_metadata(names,run_id):
    return {'total_count':len(names),'jobs':[{'id':i+1,'run_id':run_id,'name':name,
        'status':'completed','conclusion':'success'} for i,name in enumerate(sorted(names))]}


def responses():
    return [run_metadata(CONTROL,gate.CONTROL_WORKFLOW,123),job_metadata(gate.CONTROL_JOB_NAMES,123),
            run_metadata(gate.APP_SOURCE,gate.APP_WORKFLOW,gate.APP_CI_RUN),
            job_metadata(gate.APP_JOB_NAMES,gate.APP_CI_RUN)]


class GateTests(unittest.TestCase):
    def test_exact_release_and_four_operations(self):
        self.assertEqual(gate.APP_SOURCE,'be398c636bbb9ba18590a7edec601bbcb5f9b1f4')
        self.assertEqual(gate.APP_CI_RUN,42197895494)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'request.json'
            for operation in sorted(gate.OPERATIONS):
                path.write_text(json.dumps(request(operation)))
                self.assertEqual(gate.read_request(path,environment()),request(operation))

    def test_request_rejects_unknown_fields_versions_sources_and_non_uuid4(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'request.json'
            for update in [{'command':'id'},{'path':'/etc'},{'schema_version':True},{'schema_version':2},
                    {'source_sha':'a'*40},{'source_sha':'main'},{'source_sha':[]},{'operation':'upgrade-accounts'},
                    {'operation':'run-command'},{'operation':[]},{'request_id':'bad'},
                    {'request_id':'00000000-0000-0000-0000-000000000000'}]:
                path.write_text(json.dumps({**request(),**update}))
                with self.subTest(update=update),self.assertRaises((ValueError,TypeError)):
                    gate.read_request(path,environment())

    def test_origin_file_and_duplicate_guards(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'request.json';path.write_text(json.dumps(request()))
            for field in ['GITHUB_REPOSITORY','GITHUB_REF','GITHUB_EVENT_NAME']:
                with self.subTest(field=field),self.assertRaises(ValueError):gate.read_request(path,{**environment(),field:'wrong'})
            link=Path(directory)/'link.json';link.symlink_to(path)
            with self.assertRaises(ValueError):gate.read_request(link,environment())
            link.unlink();os.link(path,link)
            with self.assertRaises(ValueError):gate.read_request(path,environment())
            link.unlink();path.write_text('{"operation":"audit-application","operation":"upgrade-application"}')
            with self.assertRaises(ValueError):gate.read_request(path,environment())
            path.write_bytes(b'x'*1025)
            with self.assertRaises(ValueError):gate.read_request(path,environment())

    def test_control_checkout_pins_sha_and_tracked_bytes(self):
        runner=Mock(side_effect=[types.SimpleNamespace(returncode=0,stdout=(CONTROL+'\n').encode()),types.SimpleNamespace(returncode=0)])
        self.assertTrue(gate.control_checkout_matches(environment(),runner=runner))
        self.assertTrue(all(call.kwargs['shell'] is False for call in runner.call_args_list))
        runner=Mock(return_value=types.SimpleNamespace(returncode=0,stdout=('a'*40+'\n').encode()))
        self.assertFalse(gate.control_checkout_matches(environment(),runner=runner))
        self.assertFalse(gate.control_checkout_matches({**environment(),'QUANTA_APPLICATION_CONTROL_SHA':'main'}))

    def authorize(self,data=None):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'request.json';path.write_text(json.dumps(request()))
            with patch.object(gate,'control_checkout_matches',return_value=True),patch.object(gate,'api_get',side_effect=responses() if data is None else data) as api:
                return gate.authorize(environment(),path=path),api.call_args_list

    def test_authorization_checks_exact_two_completed_native_matrices(self):
        result,calls=self.authorize()
        self.assertEqual(result['status'],'authorized');self.assertEqual(result['app_ci_run'],gate.APP_CI_RUN)
        self.assertEqual([call.args[0] for call in calls],[
            '/actions/runs/123','/actions/runs/123/jobs?filter=latest&per_page=100',
            '/actions/runs/'+str(gate.APP_CI_RUN),'/actions/runs/'+str(gate.APP_CI_RUN)+'/jobs?filter=latest&per_page=100'])

    def test_app_and_control_metadata_cannot_be_substituted(self):
        for index in [0,2]:
            for field,bad in [('id',False),('head_sha','a'*40),('head_branch','ops/oci'),('event','workflow_dispatch'),
                              ('path','other.yml'),('status','in_progress'),('conclusion','failure')]:
                value=responses();value[index][field]=bad
                with self.subTest(index=index,field=field):self.assertEqual(self.authorize(value)[0]['status'],'denied')

    def test_native_job_matrix_missing_skipped_duplicate_or_wrong_run_is_denied(self):
        mutations=[lambda v:v.update(total_count=1),lambda v:v.update(total_count=True),
            lambda v:v['jobs'].pop(),lambda v:v['jobs'][0].update(status='in_progress'),
            lambda v:v['jobs'][0].update(conclusion='skipped'),lambda v:v['jobs'][0].update(name='emulated ARM'),
            lambda v:v['jobs'][0].update(run_id=999),lambda v:v['jobs'][0].update(id=True),
            lambda v:v['jobs'][0].update(name=v['jobs'][1]['name']),lambda v:v['jobs'][0].update(id=v['jobs'][1]['id'])]
        for index in [1,3]:
            for mutate in mutations:
                value=responses();mutate(value[index])
                with self.subTest(index=index,mutation=mutations.index(mutate)):self.assertEqual(self.authorize(value)[0]['status'],'denied')

    def test_redirect_oversize_and_bad_token_do_not_expose_credentials(self):
        class Response:
            status=200
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def geturl(self):return 'https://other.invalid/'
            def read(self,limit):return b'{}'
        with self.assertRaises(ValueError):gate.api_get('/actions/runs/123',environment(),opener=lambda *a,**k:Response())
        response=Response();response.geturl=lambda:gate.API_ROOT+'/actions/runs/123';response.read=lambda limit:b'x'*(gate.MAX_RESPONSE+1)
        with self.assertRaises(ValueError):gate.api_get('/actions/runs/123',environment(),opener=lambda *a,**k:response)
        opener=Mock()
        with self.assertRaises(ValueError):gate.api_get('/actions/runs/123',{**environment(),'QUANTA_CI_READ_TOKEN':'bad\nvalue'},opener=opener)
        opener.assert_not_called()


class FixedProgramTests(unittest.TestCase):
    def test_compressed_program_has_bounded_command_and_exact_argv(self):
        source='import json,sys\nprint(json.dumps(sys.argv[1:]))\n'
        config=b'{"synthetic":"config"}'
        command=transport.remote_command(source,config,'audit-application')
        parts=shlex.split(command)
        self.assertEqual(parts[:6],['/usr/bin/sudo','-n','/usr/bin/python3','-I','-B','-c'])
        self.assertLess(len(command.encode()),transport.MAX_ARGUMENT)
        result=subprocess.run([sys.executable,'-I','-B','-c',*parts[6:]],capture_output=True,check=False,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout),[base64.b64encode(config).decode(),'audit-application'])

    def test_changed_truncated_and_trailing_compressed_program_are_rejected(self):
        command=shlex.split(transport.remote_command('print("safe")',b'{}','audit-application'))
        raw=base64.b64decode(command[7])
        for packed in [raw[:-1],raw+b'junk',b'invalid']:
            args=[*command[6:]];args[1]=base64.b64encode(packed).decode()
            result=subprocess.run([sys.executable,'-I','-B','-c',*args],capture_output=True,check=False,timeout=5)
            self.assertNotEqual(result.returncode,0);self.assertNotIn(b'safe',result.stdout)
        other=shlex.split(transport.remote_command('print("other")',b'{}','audit-application'))
        args=[*command[6:]];args[1]=other[7]
        result=subprocess.run([sys.executable,'-I','-B','-c',*args],capture_output=True,check=False,timeout=5)
        self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'')

    def test_program_limits_and_operation_cannot_be_overridden(self):
        for source,operation in [('', 'audit-application'),('x'*196609,'audit-application'),('print(1)\0','audit-application'),('print(1)','whoami')]:
            with self.subTest(operation=operation),self.assertRaises((ValueError,SyntaxError)):transport.remote_command(source,b'{}',operation)


class TransportTests(unittest.TestCase):
    def env(self):
        return {**environment(),'QUANTA_OCI_AUTH_CONFIRMED':'true','QUANTA_APPLICATION_OPERATION':'upgrade-application',
            'QUANTA_APPLICATION_SOURCE_SHA':gate.APP_SOURCE,'QUANTA_APPLICATION_REQUEST_ID':REQUEST_ID,
            'QUANTA_PUBLIC_ORIGIN':'https://app.example.net','QUANTA_AUTH_MODE':'owner-token',
            'QUANTA_OCI_HOST':'192.0.2.1','QUANTA_OCI_HOST_KEY':'synthetic','QUANTA_OCI_PPK':'synthetic'}

    def modules(self,approved=None):
        safe={'scope':'application_upgrade','operation':'upgrade-application','status':'success'}
        def sanitize(raw):
            try:value=json.loads(raw)
            except (ValueError,TypeError):return None
            return value if set(value)==set(safe) else None
        controller=types.SimpleNamespace(validate_config=lambda v:v,_encoded=lambda v:json.dumps(v).encode(),sanitize_report=sanitize)
        login=types.SimpleNamespace(PLINK='/usr/bin/plink',_normalized_host_key=lambda v:'SHA256:synthetic',
            _key_bytes=Mock(return_value=(None,b'PRIVATE_SYNTHETIC_PPK')),_global_ipv4=lambda v:True)
        modules={'authorize_application_upgrade':types.SimpleNamespace(control_checkout_matches=lambda env:True,
                    read_request=lambda **kwargs:request() if approved is None else approved),
            'upgrade_application':controller,'probe_login':login,'probe_inventory':types.SimpleNamespace()}
        return modules,safe

    def test_private_key_file_and_fixed_existing_transport_flags(self):
        modules,safe=self.modules();captured={}
        def runner(command,environment,directory):
            key=Path(command[command.index('-i')+1]);self.assertEqual(key.read_bytes(),b'PRIVATE_SYNTHETIC_PPK')
            self.assertEqual(stat.S_IMODE(key.stat().st_mode),0o600);self.assertEqual(stat.S_IMODE(Path(directory).stat().st_mode),0o700)
            self.assertNotIn('QUANTA_OCI_PPK',environment);self.assertEqual(environment['PATH'],'/usr/bin:/bin')
            self.assertLess(len(command[-1].encode()),transport.MAX_ARGUMENT)
            captured.update(command=command,key_path=key)
            return 'success',json.dumps(safe).encode(),True
        with patch.object(transport,'_module',side_effect=lambda name:modules[name]),patch.object(Path,'read_text',return_value='print("safe")'):
            result=transport.probe(self.env(),runner=runner)
        self.assertEqual(result['status'],'success');self.assertTrue(result['authentication_attempted'])
        self.assertIn('-hostkey',captured['command']);self.assertIn('-noagent',captured['command']);self.assertIn('-batch',captured['command'])
        self.assertFalse(captured['key_path'].exists());self.assertNotIn('PRIVATE_SYNTHETIC_PPK',json.dumps(result))

    def test_mismatched_request_and_oversized_program_fail_before_key_use(self):
        for approved,source in [({**request(),'request_id':'wrong'},'print("safe")'),(request(),'x'*196609)]:
            modules,_=self.modules(approved)
            with patch.object(transport,'_module',side_effect=lambda name:modules[name]),patch.object(Path,'read_text',return_value=source):
                result=transport.probe(self.env(),runner=Mock())
            self.assertEqual(result['status'],'configuration_invalid');modules['probe_login']._key_bytes.assert_not_called()
            self.assertFalse(result['authentication_attempted'])

    def test_unconfirmed_or_nonfixed_operation_never_loads_keys(self):
        for update in [{'QUANTA_OCI_AUTH_CONFIRMED':'false'},{'QUANTA_APPLICATION_OPERATION':'upgrade-accounts'},
                       {'QUANTA_APPLICATION_OPERATION':[]}]:
            with patch.object(transport,'_module') as loader:result=transport.probe({**self.env(),**update})
            self.assertEqual(result['status'],'not_configured');loader.assert_not_called()

    def test_remote_output_cannot_inject_secrets_or_mismatched_operation(self):
        modules,safe=self.modules()
        for raw in [json.dumps({**safe,'owner_token':'PRIVATE'}).encode(),json.dumps({**safe,'operation':'audit-application'}).encode(),b'not-json']:
            with patch.object(transport,'_module',side_effect=lambda name:modules[name]),patch.object(Path,'read_text',return_value='print("safe")'):
                result=transport.probe(self.env(),runner=lambda *a:('success',raw,True))
            self.assertIn(result['status'],['invalid_output','failed']);self.assertNotIn('PRIVATE',json.dumps(result))

    def test_timeout_and_failed_client_never_return_unsanitized_bytes(self):
        modules,_=self.modules()
        for status in ['timeout','output_limit','failed']:
            with patch.object(transport,'_module',side_effect=lambda name:modules[name]),patch.object(Path,'read_text',return_value='print("safe")'):
                result=transport.probe(self.env(),runner=lambda *a:(status,b'SECRET_RAW',True))
            self.assertIn(result['status'],['timeout','output_limit','remote_failed']);self.assertNotIn('SECRET_RAW',json.dumps(result))


class WorkflowTests(unittest.TestCase):
    def test_dispatch_is_new_fixed_path_and_independently_pinned_before_credentials(self):
        text=(ROOT/'.github/workflows/oci-application.yml').read_text()
        self.assertIn('.github/oci/application-request.json',text)
        self.assertIn('group: quanta-oci-installation',text)
        self.assertIn('environment: oci-preflight',text)
        self.assertIn('timeout-minutes: 35',text)
        self.assertLess(text.index('authorize_application_upgrade.py'),text.index('${{ secrets.QUANTA_OCI_PPK }}'))
        self.assertIn('verified-application-control/deploy/oci/probe_application_upgrade.py',text)
        self.assertNotIn('run-command',text)

    def test_control_ci_runs_native_arches_and_all_application_tests(self):
        text=(ROOT/'.github/workflows/oci-application-tests.yml').read_text()
        self.assertIn('application control (${{ matrix.architecture }})',text)
        self.assertIn('ubuntu-24.04-arm',text);self.assertIn('3.12.14',text)
        self.assertIn("'test_oci_application*.py'",text)


if __name__=='__main__':unittest.main()
