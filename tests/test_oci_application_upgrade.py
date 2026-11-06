"""Fixed application upgrade safety: local SQLite/files only, no remote actions."""
from __future__ import annotations

import base64
from contextlib import ExitStack, contextmanager, nullcontext
from copy import deepcopy
import gzip
import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import tarfile
import tempfile
import types
import unittest
from unittest.mock import Mock, call, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('test_fixed_application_controller', ROOT / 'deploy/oci/upgrade_application.py')
operation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(operation)

SHA = '5723290fc5f4ec9a6fa3b167f00745b18fc03a59'
OLD_SOURCE = 'be398c636bbb9ba18590a7edec601bbcb5f9b1f4'
REQUEST_ID = '6265bde1-e559-45b3-87c2-14a41fd3251d'
OLD_IMAGE = 'sha256:' + 'c' * 64
NEW_IMAGE = 'sha256:' + 'd' * 64
TOKEN = 'e' * 64
JOBS_TABLES = ('artifacts', 'events', 'experiments', 'idempotency', 'revisions', 'runs')
AUTH_TABLES = ('accounts', 'challenges', 'meta', 'rate_windows', 'sessions')
MAIL_FILES = ('gmail-smtp.json', 'gmail-budget.json', 'gmail-mail.lock')


def config():
    return {'source_sha': SHA, 'request_id': REQUEST_ID, 'public_origin': 'https://app.example.net', 'auth_mode': 'owner-token'}


def databases():
    def one(tables, jobs=False):
        result = {'schema_sha256': 'a' * 64, 'pragmas': {'user_version': 0, 'application_id': 0},
                  'tables': {name: {'rows': i+1, 'sha256': 'b'*64} for i,name in enumerate(tables)}}
        if jobs: result['nonterminal_runs'] = 0
        return result
    return {'jobs': one(JOBS_TABLES, True), 'auth': one(AUTH_TABLES)}


def mail_settings():
    return {name: {'present': True, 'sha256': 'f'*64, 'uid':10001, 'gid':10001, 'mode':0o600} for name in MAIL_FILES}


def deployment():
    return {'storage_mode':'boot', 'filesystem_uuid':'540c2fb0-7424-48d8-8b0a-fef3cb15b539', 'image':OLD_IMAGE}


def journal():
    return {'schema_version':1, 'request_id':REQUEST_ID, 'source_sha':SHA,
        'created_at':'2026-11-06T01:02:03Z', 'status':'switching', 'database':databases(),
        'mail_settings':mail_settings(), 'settings':{'synthetic':'f'*64},
        'old_deployment':base64.b64encode(operation._encoded(deployment())).decode(),
        'new_deployment':base64.b64encode(operation._encoded({**deployment(),'image':NEW_IMAGE})).decode(),
        'old_installed':base64.b64encode(operation._encoded({'source_sha':OLD_SOURCE,
            'public_origin':config()['public_origin'],'auth_mode':'owner-token'})).decode(),
        'new_installed':base64.b64encode(operation._encoded({k:v for k,v in config().items() if k!='request_id'})).decode()}


@contextmanager
def fake_upgrade():
    saved=journal()
    with ExitStack() as stack, tempfile.TemporaryDirectory() as temporary:
        stack.enter_context(patch.object(operation,'JOURNAL',Path(temporary)/'absent.json'))
        mocks={}
        values={'_lock':nullcontext(), '_interruptions':nullcontext(), '_services':None,
            '_containers':None, '_worker':None, '_databases':databases(), '_mail_settings':mail_settings(),
            '_stage':Path('/synthetic/source'), '_build':NEW_IMAGE, '_smoke':None, '_quiet':None,
            '_write_journal':None, '_arm_watchdog':None, '_cancel_watchdog':None,
            '_replace':None, '_public':None, '_restore':None,
            '_unit':{'LoadState':'not-found','ActiveState':'inactive'}}
        for name,value in values.items():mocks[name]=stack.enter_context(patch.object(operation,name,return_value=value))
        def installation(_config,*,new=False):
            return ({**deployment(),'image':NEW_IMAGE if new else OLD_IMAGE},
                base64.b64decode(saved['new_deployment' if new else 'old_deployment']),
                base64.b64decode(saved['new_installed' if new else 'old_installed']),saved['settings'],TOKEN)
        mocks['_installation']=stack.enter_context(patch.object(operation,'_installation',side_effect=installation))
        def readiness(_config,token,*,new,report):
            report.update(services_ready=True,auth_boundaries_verified=True,account_discovery_verified=True,
                          application_version='0.16.0' if new else '0.15.0',mail_configured=True,registration='open')
            if new:report['dynamics_capability_verified']=True
        mocks['_readiness']=stack.enter_context(patch.object(operation,'_readiness',side_effect=readiness))
        state={'journal':None}
        def read_journal():
            if state['journal'] is None:raise FileNotFoundError()
            return deepcopy(state['journal'])
        def write_journal(value):state['journal']=deepcopy(value)
        def update_journal(value,status):
            state['journal']={**deepcopy(value),'status':status};return deepcopy(state['journal'])
        mocks['_write_journal'].side_effect=write_journal
        mocks['_journal_status']=stack.enter_context(patch.object(operation,'_journal_status',side_effect=update_journal))
        mocks['_journal']=stack.enter_context(patch.object(operation,'_journal',side_effect=read_journal))
        mocks['_unit'].side_effect=lambda unit,props: {'ActiveState':'inactive'} if unit==operation.APP and props==('ActiveState',) else {'LoadState':'not-found','ActiveState':'inactive'}
        stack.enter_context(patch.object(operation,'_deadline',side_effect=lambda seconds:nullcontext()))
        stack.enter_context(patch.object(operation.time,'sleep'))
        yield mocks


def successful_report():
    with fake_upgrade():return operation.run(config(),'upgrade-application')


class ControllerTests(unittest.TestCase):
    def test_exact_release_config_and_no_arbitrary_command(self):
        value=operation._encoded(config())
        self.assertEqual(operation._argument(base64.b64encode(value).decode()),config())
        for update in ({'source_sha':OLD_SOURCE},{'source_sha':'a'*40},{'source_sha':'main'},
                {'auth_mode':'access'},{'public_origin':'http://app.example.net'},
                {'public_origin':'https://app.example.net/path'},{'request_id':'bad'},{'command':'id'}):
            with self.subTest(update=update),self.assertRaises((ValueError,TypeError)):
                operation.validate_config({**config(),**update})

    def test_definitive_dual_database_and_mail_baseline_follows_complete_app_stop(self):
        with fake_upgrade() as mocks:
            events=[]
            for name in ('_arm_watchdog','_write_journal','_replace','_quiet','_databases','_mail_settings'):
                original=mocks[name].side_effect;value=mocks[name].return_value
                def event(*args,_name=name,_original=original,_value=value,**kwargs):
                    events.append((_name,args))
                    return _original(*args,**kwargs) if callable(_original) else _value
                mocks[name].side_effect=event
            result=operation.run(config(),'upgrade-application')
        self.assertEqual(result['status'],'success',result)
        operation.validate_report(result)
        index=lambda name:next(i for i,x in enumerate(events) if x[0]==name)
        stop=lambda unit:next(i for i,x in enumerate(events) if x[0]=='_quiet' and x[1][0]==['/usr/bin/systemctl','stop',unit])
        self.assertLess(index('_arm_watchdog'),stop(operation.HTTPS))
        self.assertLess(stop(operation.HTTPS),stop(operation.APP))
        self.assertLess(stop(operation.TIMER),stop(operation.APP))
        private=index('_write_journal');self.assertLess(stop(operation.APP),private);self.assertLess(private,index('_replace'))
        before=[x for x in events[stop(operation.APP)+1:private] if x[0]=='_databases']
        self.assertGreaterEqual(len(before),1)
        saved=mocks['_write_journal'].call_args.args[0]
        self.assertEqual(saved['database'],databases());self.assertEqual(saved['mail_settings'],mail_settings())
        for flag in ('database_preserved','auth_database_preserved','mail_settings_preserved','settings_preserved'):
            self.assertTrue(result[flag],flag)

    def test_busy_or_untrusted_installation_refuses_before_service_stops(self):
        for name in ('_installation','_services','_containers','_worker','_databases','_mail_settings'):
            with self.subTest(name=name),fake_upgrade() as mocks:
                mocks[name].side_effect=operation.UpgradeError()
                report=operation.run(config(),'upgrade-application')
                self.assertEqual(report['status'],'failed');mocks['_quiet'].assert_not_called();mocks['_replace'].assert_not_called()

    def test_existing_journal_blocks_upgrade_and_source_staging(self):
        with fake_upgrade() as mocks,tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'existing';p.write_bytes(b'operator-owned')
            mocks['_journal'].side_effect=None;mocks['_journal'].return_value=journal()
            with patch.object(operation,'JOURNAL',p):result=operation.run(config(),'upgrade-application')
            self.assertEqual(result['status'],'failed');mocks['_stage'].assert_not_called()

    def test_completed_upgrade_resumes_without_rebuilding_or_old_configuration_switch(self):
        with fake_upgrade() as mocks:
            mocks['_journal'].side_effect=None;mocks['_journal'].return_value={**journal(),'status':'complete'}
            result=operation.run(config(),'upgrade-application')
            self.assertEqual(result['status'],'success',result);self.assertTrue(result['committed_resume'])
            for name in ('_stage','_build','_replace','_write_journal','_restore'):mocks[name].assert_not_called()

    def test_committed_operations_refuse_an_operator_changed_image(self):
        for requested_operation in ('upgrade-application','verify-application','smoke-application'):
            with self.subTest(operation=requested_operation),fake_upgrade() as mocks:
                mocks['_journal'].side_effect=None;mocks['_journal'].return_value={**journal(),'status':'complete'}
                original=mocks['_installation'].side_effect
                def operator_image(*args,**kwargs):
                    value=list(original(*args,**kwargs))
                    value[0]={**value[0],'image':'sha256:'+'9'*64}
                    value[1]=operation._encoded(value[0])
                    return tuple(value)
                mocks['_installation'].side_effect=operator_image
                result=operation.run(config(),requested_operation)
                self.assertEqual(result['status'],'failed');self.assertFalse(result['rollback_attempted'])
                for name in ('_quiet','_readiness','_stage','_build','_replace','_restore','_public'):
                    mocks[name].assert_not_called()

    def test_readonly_verify_uses_committed_proof_not_stale_live_auth_or_mail_rows(self):
        with fake_upgrade() as mocks:
            mocks['_journal'].side_effect=None;mocks['_journal'].return_value={**journal(),'status':'complete'}
            current=databases();current['auth']['tables']['sessions']['sha256']='0'*64
            mocks['_databases'].return_value=current
            mocks['_mail_settings'].return_value={**mail_settings(),'gmail-budget.json':{'present':True,'sha256':'0'*64}}
            result=operation.run(config(),'verify-application')
            self.assertEqual(result['status'],'success',result)
            self.assertEqual(result['preservation_scope'],'committed_upgrade')
            for name in ('_quiet','_stage','_build','_replace','_write_journal','_restore'):mocks[name].assert_not_called()

    def test_readonly_audit_can_observe_live_queued_work_without_stopping_services(self):
        with fake_upgrade() as mocks:
            current=databases();current['jobs']['nonterminal_runs']=2;mocks['_databases'].return_value=current
            result=operation.run(config(),'audit-application')
            self.assertEqual(result['status'],'success',result);self.assertEqual(result['active_runs'],2)
            mocks['_databases'].assert_called_with(require_idle=False)
            for name in ('_quiet','_stage','_build','_replace','_write_journal','_restore'):mocks[name].assert_not_called()

    def test_backup_in_progress_cannot_be_forced_through(self):
        with fake_upgrade() as mocks:
            mocks['_unit'].side_effect=None
            mocks['_unit'].return_value={'LoadState':'loaded','ActiveState':'active'}
            result=operation.run(config(),'upgrade-application')
            self.assertEqual(result['status'],'failed');mocks['_replace'].assert_not_called()

    def test_failure_after_switch_uses_only_recorded_old_configuration(self):
        with fake_upgrade() as mocks:
            ready=mocks['_readiness'].side_effect
            def fail_new(*args,**kwargs):
                if kwargs['new']:raise operation.UpgradeError()
                return ready(*args,**kwargs)
            mocks['_readiness'].side_effect=fail_new
            result=operation.run(config(),'upgrade-application')
            self.assertEqual(result['status'],'failed');self.assertTrue(result['rollback_attempted']);self.assertTrue(result['rollback_succeeded'])
            saved=mocks['_restore'].call_args.args[0]
            self.assertEqual(base64.b64decode(saved['old_deployment']),operation._encoded(deployment()))

    def test_config_rollback_cannot_claim_a_changed_auth_database_was_restored(self):
        with fake_upgrade() as mocks:
            ready=mocks['_readiness'].side_effect
            def fail_new(*args,**kwargs):
                if kwargs['new']:raise operation.UpgradeError()
                return ready(*args,**kwargs)
            mocks['_readiness'].side_effect=fail_new
            def current():
                value=databases()
                if mocks['_restore'].called:value['auth']['tables']['sessions']['sha256']='0'*64
                return value
            mocks['_databases'].side_effect=current
            result=operation.run(config(),'upgrade-application')
            self.assertTrue(result['rollback_attempted']);self.assertFalse(result['rollback_succeeded'])

    def test_config_rollback_cannot_claim_changed_smtp_files_were_restored(self):
        with fake_upgrade() as mocks:
            ready=mocks['_readiness'].side_effect
            def fail_new(*args,**kwargs):
                if kwargs['new']:raise operation.UpgradeError()
                return ready(*args,**kwargs)
            mocks['_readiness'].side_effect=fail_new
            mocks['_mail_settings'].side_effect=lambda:{**mail_settings(),'gmail-smtp.json':{'present':False}} if mocks['_restore'].called else mail_settings()
            result=operation.run(config(),'upgrade-application')
            self.assertTrue(result['rollback_attempted']);self.assertFalse(result['rollback_succeeded'])

    def test_unpublished_partial_journal_failure_restores_services_without_replacing_files(self):
        with fake_upgrade() as mocks:
            mocks['_write_journal'].side_effect=InterruptedError('synthetic interrupted publication')
            mocks['_journal'].side_effect=FileNotFoundError()
            result=operation.run(config(),'upgrade-application')
            self.assertEqual(result['status'],'failed');mocks['_replace'].assert_not_called();mocks['_restore'].assert_not_called()
            self.assertTrue(result['rollback_succeeded'])

    def test_late_watchdog_cleanup_cannot_undo_committed_upgrade(self):
        with fake_upgrade() as mocks:
            mocks['_cancel_watchdog'].side_effect=operation.UpgradeError()
            result=operation.run(config(),'upgrade-application')
            self.assertEqual(result['status'],'success');self.assertFalse(result['rollback_attempted']);mocks['_restore'].assert_not_called()

    def test_public_failure_after_commit_never_rolls_back_user_admitted_new_app(self):
        with fake_upgrade() as mocks:
            events=[]
            original=mocks['_journal_status'].side_effect
            def commit(value,status):events.append('commit');return original(value,status)
            def public(*args):events.append('public');raise operation.UpgradeError()
            mocks['_journal_status'].side_effect=commit;mocks['_public'].side_effect=public
            result=operation.run(config(),'upgrade-application')
            self.assertLess(events.index('commit'),events.index('public'))
            self.assertFalse(result['rollback_attempted']);mocks['_restore'].assert_not_called()

    def test_visible_complete_commit_survives_fsync_error_before_public_resume(self):
        with fake_upgrade() as mocks:
            def commit_then_fail(value,status):
                mocks['_journal'].side_effect=None
                mocks['_journal'].return_value={**value,'status':status}
                raise OSError('synthetic fsync error after complete marker publication')
            mocks['_journal_status'].side_effect=commit_then_fail
            mocks['_public'].side_effect=operation.UpgradeError()
            result=operation.run(config(),'upgrade-application')
            self.assertEqual(result['status'],'failed')
            self.assertTrue(result['commit_visible_after_error'])
            self.assertFalse(result['rollback_attempted']);mocks['_restore'].assert_not_called()
            self.assertFalse(result['public_https_verified'])
            self.assertEqual(operation.sanitize_report(operation._encoded(result)),result)

    def test_report_sanitizer_never_exports_secrets_or_private_digest_material(self):
        value=successful_report()
        self.assertEqual(value['status'],'success',value)
        for update in ({'owner_token':TOKEN},{'password':'synthetic-private'},
                {'database':databases()},{'mail_settings':mail_settings()},{'source_path':'/private'},
                {'peer_containers':True},{'status':[]},{'application_version':'0.15.0'},
                {'mail_delivery_verified':True},{'auth_database_preserved':False},
                {'mail_settings_preserved':False},{'dynamics_capability_verified':False}):
            with self.subTest(update=update):self.assertIsNone(operation.sanitize_report(operation._encoded({**value,**update})))

    def test_fixed_watchdog_is_compileable_namespaced_and_contains_no_secret_literal(self):
        source=operation._watchdog_source();compile(source,'<application-watchdog>','exec')
        self.assertIn(b'/etc/quanta/application-upgrade-0.16.json',source)
        self.assertNotIn(b"P=pathlib.Path('/etc/quanta/application-upgrade.json')",source)
        self.assertIn(b'/etc/quanta/.application-upgrade-0.16.publish',source)
        self.assertIn(b'/run/quanta-application-upgrade.lock',source)
        self.assertEqual(operation.ROLLBACK_SCRIPT,Path('/usr/local/lib/quanta/application-rollback-0.16.py'))
        self.assertEqual(operation.WATCHDOG,'quanta-application-rollback-0-16')
        self.assertNotIn(TOKEN.encode(),source);self.assertNotIn(b'accounts-upgrade.json',source)
        self.assertNotIn(b'rmtree',source)

    def test_interruption_handler_restores_original_handlers(self):
        import signal
        before={number:signal.getsignal(number) for number in (signal.SIGTERM,signal.SIGHUP)}
        with self.assertRaises(operation.UpgradeError):
            with operation._interruptions():
                signal.getsignal(signal.SIGTERM)(signal.SIGTERM,None)
        self.assertEqual({number:signal.getsignal(number) for number in before},before)

    def readiness_values(self):
        return [(200,{'status':'ready'}),(401,{}),(401,{}),
            (200,{'package_version':'0.16.0','contract_version':'0.2.0',
                  'supported_experiment_versions':['0.2.0','0.4.0'],
                  'experiment_contracts':{'0.4.0':{'implemented_operations':{'quanta.pair_dynamics@0.1.0':['integrate']}}}}),
            (200,{'mode':'account','authenticated':False,'mail_configured':True,'registration':'open'})]

    def test_readiness_requires_target_capabilities_and_cookie_free_account_discovery(self):
        value=operation._initial('verify-application')
        with patch.object(operation,'_http',side_effect=self.readiness_values()) as http, patch.object(operation,'_web_assets') as assets:
            operation._readiness(config(),TOKEN,new=True,report=value)
        self.assertTrue(value['dynamics_capability_verified']);self.assertTrue(value['mail_configured'])
        self.assertEqual(http.call_args_list[-1],call(config(),'/ui/auth'));assets.assert_called_once_with(config())

    def test_readiness_refuses_wrong_version_missing_dynamics_or_authenticated_discovery(self):
        for mutation in ('old_version','no_dynamics','session_cookie'):
            values=self.readiness_values()
            if mutation=='old_version':values[3][1]['package_version']='0.15.0'
            elif mutation=='no_dynamics':values[3][1]['experiment_contracts']={}
            else:values[4][1]['authenticated']=True
            with self.subTest(mutation=mutation),patch.object(operation,'_http',side_effect=values),patch.object(operation,'_web_assets'),self.assertRaises(operation.UpgradeError):
                operation._readiness(config(),TOKEN,new=True,report=operation._initial('verify-application'))


class WebAssetTests(unittest.TestCase):
    def pins(self):
        return {'/':{'size_bytes':6,'sha256':hashlib.sha256(b'Quanta').hexdigest()},
                '/assets/dynamics-viewer.mjs':{'size_bytes':4,'sha256':hashlib.sha256(b'view').hexdigest()}}

    def test_exact_frozen_assets_match_candidate_source_bytes(self):
        self.assertEqual(set(operation.WEB_ASSETS),{'/','/assets/app.js','/assets/view-model.mjs',
            '/assets/dynamics-evidence.mjs','/assets/dynamics-model.mjs',
            '/assets/dynamics-viewer.mjs','/assets/dynamics-viewer.css'})
        for path,expected in operation.WEB_ASSETS.items():
            relative='index.html' if path=='/' else path.rsplit('/',1)[1]
            raw=(ROOT/'src/quanta/web'/relative).read_bytes()
            operation._check_web_asset(path,200,raw)
            self.assertLessEqual(expected['size_bytes'],1024**2)

    def test_private_assets_are_exact_bounded_requests_without_credentials(self):
        with patch.object(operation,'WEB_ASSETS',self.pins()),patch.object(operation,'_api',side_effect=[(200,b'Quanta'),(200,b'view')]) as api:
            operation._web_assets(config())
        self.assertEqual(api.call_args_list,[
            call(config(),'GET','/',maximum=6,raw_response=True),
            call(config(),'GET','/assets/dynamics-viewer.mjs',maximum=4,raw_response=True)])

    def test_private_missing_tampered_truncated_and_overlong_assets_fail_closed(self):
        for response in ((404,b'view'),(200,b'evil'),(200,b'vie'),(200,b'views'),(200,'view')):
            with self.subTest(response=response),patch.object(operation,'WEB_ASSETS',self.pins()), \
                    patch.object(operation,'_api',side_effect=[(200,b'Quanta'),response]),self.assertRaises(operation.UpgradeError):
                operation._web_assets(config())

    def test_readiness_cannot_succeed_when_new_asset_proof_fails(self):
        report=operation._initial('verify-application')
        with patch.object(operation,'_http',side_effect=ControllerTests().readiness_values()), \
                patch.object(operation,'_web_assets',side_effect=operation.UpgradeError()),self.assertRaises(operation.UpgradeError):
            operation._readiness(config(),TOKEN,new=True,report=report)
        self.assertFalse(report['services_ready']);self.assertFalse(report['dynamics_capability_verified'])

    def public(self,values,*,new=True):
        requests=[];reads=[];closed=[]
        class Response:
            def __init__(self,status,raw):self.status=status;self.raw=raw
            def read(self,limit):reads.append(limit);return self.raw[:limit]
        class Connection:
            def __init__(self,host,port,**kwargs):
                self.values=iter(values);self.host=host;self.port=port
                self.value=None
            def request(self,method,path,headers):
                requests.append((method,path,headers));self.value=values[path]
            def getresponse(self):return Response(*self.value)
            def close(self):closed.append(True)
        with patch.object(operation,'WEB_ASSETS',self.pins()),patch.object(operation.http.client,'HTTPSConnection',Connection):
            operation._public(config(),new)
        return requests,reads,closed

    def test_public_https_assets_are_exact_bounded_and_cookie_free(self):
        requests,reads,closed=self.public({'/':(200,b'Quanta'),'/assets/dynamics-viewer.mjs':(200,b'view')})
        self.assertEqual([item[:2] for item in requests],[('GET','/'),('GET','/assets/dynamics-viewer.mjs')])
        self.assertTrue(all(item[2]=={'Connection':'close'} for item in requests))
        self.assertEqual(reads,[7,5]);self.assertEqual(len(closed),2)

    def test_public_https_refuses_any_wrong_status_size_or_sha(self):
        for response in ((404,b'view'),(200,b'evil'),(200,b'vie'),(200,b'views')):
            with self.subTest(response=response),self.assertRaises(operation.UpgradeError):
                self.public({'/':(200,b'Quanta'),'/assets/dynamics-viewer.mjs':response})

    def test_old_release_audit_uses_old_shell_without_new_asset_assumptions(self):
        requests,reads,closed=self.public({'/':(200,b'<html>Quanta older shell</html>')},new=False)
        self.assertEqual(len(requests),1);self.assertEqual(reads,[1024**2+1]);self.assertEqual(len(closed),1)


class LocalDatabaseTests(unittest.TestCase):
    @contextmanager
    def stores(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for filename,tables in [('jobs.sqlite3',JOBS_TABLES),('auth.sqlite3',AUTH_TABLES)]:
                with sqlite3.connect(root/filename) as db:
                    for table in tables:
                        fields='(seq INTEGER PRIMARY KEY AUTOINCREMENT,value BLOB)' if table=='experiments' else '(status TEXT)' if table=='runs' else '(value BLOB)'
                        db.execute('CREATE TABLE '+table+' '+fields)
                        if table=='experiments':db.execute('INSERT INTO experiments(value) VALUES(?)',(b'original',))
                        else:db.execute('INSERT INTO '+table+' VALUES(?)',('SUCCEEDED' if table=='runs' else b'\0original\xff',))
                    db.execute('PRAGMA user_version=7');db.execute('PRAGMA application_id=127')
                (root/filename).chmod(0o600)
            original=os.lstat
            def private_info(path,*args,**kwargs):
                value=original(path,*args,**kwargs)
                if str(path).startswith(str(root)):
                    fields=list(value);fields[4]=fields[5]=10001;return os.stat_result(fields)
                return value
            with patch.object(operation,'DATA',root),patch.object(operation,'_store_identity',return_value=nullcontext()),patch.object(operation.os,'lstat',side_effect=private_info):
                yield root

    def test_real_dual_sqlite_inventory_covers_every_user_table_and_blob(self):
        with self.stores() as root:
            before=operation._databases();self.assertEqual(before,operation._databases())
            self.assertEqual(set(before['jobs']['tables']),set(JOBS_TABLES)|{'sqlite_sequence'})
            self.assertEqual(set(before['auth']['tables']),set(AUTH_TABLES))
            with sqlite3.connect(root/'auth.sqlite3') as db:db.execute('UPDATE sessions SET value=?',(b'\0changed\xff',))
            after=operation._databases();self.assertEqual(before['jobs'],after['jobs']);self.assertNotEqual(before['auth'],after['auth'])

    def test_sequence_and_database_pragmas_are_not_silently_ignored(self):
        with self.stores() as root:
            before=operation._databases()
            self.assertEqual(before['jobs']['pragmas'],{'user_version':7,'application_id':127})
            with sqlite3.connect(root/'jobs.sqlite3') as db:db.execute("UPDATE sqlite_sequence SET seq=99 WHERE name='experiments'")
            changed=operation._databases();self.assertNotEqual(before['jobs']['tables']['sqlite_sequence'],changed['jobs']['tables']['sqlite_sequence'])
            with sqlite3.connect(root/'auth.sqlite3') as db:db.execute('PRAGMA user_version=8')
            self.assertNotEqual(changed['auth'],operation._databases()['auth'])

    def test_each_auth_table_is_included_in_inventory(self):
        for table in AUTH_TABLES:
            with self.subTest(table=table),self.stores() as root:
                before=operation._databases()
                with sqlite3.connect(root/'auth.sqlite3') as db:db.execute('UPDATE '+table+' SET value=?',(b'updated',))
                after=operation._databases()
                self.assertNotEqual(before['auth']['tables'][table],after['auth']['tables'][table])

    def test_nonterminal_jobs_and_unknown_auth_tables_are_refused(self):
        with self.stores() as root:
            with sqlite3.connect(root/'jobs.sqlite3') as db:db.execute("UPDATE runs SET status='RUNNING'")
            with self.assertRaises(operation.UpgradeError):operation._databases()
        with self.stores() as root:
            with sqlite3.connect(root/'auth.sqlite3') as db:db.execute('CREATE TABLE unexpected(value)')
            with self.assertRaises(operation.UpgradeError):operation._databases()

    def test_auth_database_symlink_or_loose_permissions_fail_closed(self):
        with self.stores() as root:
            path=root/'auth.sqlite3';path.chmod(0o644)
            with self.assertRaises(operation.UpgradeError):operation._databases()
            path.chmod(0o600);renamed=root/'saved-auth';path.rename(renamed);path.symlink_to(renamed)
            with self.assertRaises(operation.UpgradeError):operation._databases()

    def test_typed_encoding_distinguishes_blob_text_and_negative_zero(self):
        self.assertNotEqual(operation._typed(b'a'),operation._typed('a'))
        self.assertNotEqual(operation._typed(-0.0),operation._typed(0.0))
        for value in (True,float('nan'),float('inf'),{}):
            with self.subTest(value=value),self.assertRaises(operation.UpgradeError):operation._typed(value)

    def test_live_cohort_allows_appends_and_mutable_auth_or_idempotency_cleanup(self):
        with self.stores() as root:
            before=operation._databases(include_rows=True)
            with sqlite3.connect(root/'jobs.sqlite3') as db:
                db.execute('INSERT INTO experiments(value) VALUES(?)',(b'new experiment',))
                for table in ('events','revisions','artifacts'):
                    db.execute('INSERT INTO '+table+' VALUES(?)',(b'new artifact or event',))
                db.execute("INSERT INTO runs VALUES('QUEUED')")
                db.execute('DELETE FROM idempotency')
            with sqlite3.connect(root/'auth.sqlite3') as db:
                db.execute('DELETE FROM sessions');db.execute('UPDATE rate_windows SET value=?',(b'new rate budget',))
            after=operation._databases(include_rows=True,require_idle=False)
            operation._append_only(before,after)
            self.assertNotEqual(before['auth'],after['auth'])
            self.assertEqual(after['jobs']['nonterminal_runs'],1)

    def test_live_cohort_refuses_mutation_of_each_existing_immutable_table(self):
        for table in ('experiments','revisions','runs','events','artifacts'):
            with self.subTest(table=table),self.stores() as root:
                before=operation._databases(include_rows=True)
                with sqlite3.connect(root/'jobs.sqlite3') as db:db.execute('DELETE FROM '+table)
                after=operation._databases(include_rows=True,require_idle=False)
                with self.assertRaises(operation.UpgradeError):operation._append_only(before,after)

    def test_live_cohort_refuses_schema_pragma_sequence_or_duplicate_loss(self):
        with self.stores():before=operation._databases(include_rows=True)
        for mutation in ('schema','pragma','sequence','duplicate'):
            old=deepcopy(before);after=deepcopy(before)
            if mutation=='schema':after['jobs']['schema_sha256']='0'*64
            elif mutation=='pragma':after['jobs']['pragmas']['user_version']+=1
            elif mutation=='sequence':after['jobs']['sequence']['experiments']=0
            else:old['jobs']['tables']['events']['row_hashes']*=2
            with self.subTest(mutation=mutation),self.assertRaises(operation.UpgradeError):operation._append_only(old,after)


class ScientificSmokeTests(unittest.TestCase):
    EXPERIMENT='11111111-1111-4111-8111-111111111111'
    REVISION='22222222-2222-4222-8222-222222222222'
    RUN='33333333-3333-4333-8333-333333333333'
    ARTIFACT='44444444-4444-4444-8444-444444444444'

    def api_values(self):
        raw=b'synthetic bounded trajectory artifact'
        artifact={'artifact_id':self.ARTIFACT,'size_bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
        final_system=deepcopy(operation._smoke_definition()['system'])
        final_system['particles'][0]['position_m']=[-.875,0,0]
        frames=[{'step_index':i,'time_s':i/8,
                 'positions_m':[[-1+i/64,0,0],[1,0,0]],
                 'velocities_m_per_s':[[.125,0,0],[0,0,0]]} for i in range(9)]
        result={'schema_version':'0.4.0','execution_status':'SUCCEEDED',
            'physical_validation_status':'unvalidated','partial':False,
            'steps':[{'outcome':'SUCCEEDED','numerical_status':'pass','resolution_status':'not_checked',
                'state_ref':'final-state','payload':{'partial':False,'primary_refinement_factor':1,
                'particle_ids':['left','right'],'masses_kg':[1,3],
                'legs':[{'completed_steps':8,'completed_force_evaluations':9,'sampled_frames':frames}]}}],
            'states':[{'state_id':'final-state','physical_time':{'value':1,'unit':'s'},
                'data':{'time_s':1,'system':final_system}}],
            'artifacts':[artifact]}
        return [(201,{'experiment_id':self.EXPERIMENT}),
            (201,{'revision_id':self.REVISION,'definition':operation._smoke_definition()}),
            (202,{'run_id':self.RUN}),(200,{'execution_status':'SUCCEEDED'}),
            (200,result),(200,{'artifacts':[artifact]}),(200,raw)]

    def snapshots(self):
        before=databases()
        for name,table in before['jobs']['tables'].items():table['row_hashes']=[hashlib.sha256(name.encode()).hexdigest()]
        before['jobs']['sequence']={'experiments':1,'events':1,'runs':1}
        after=deepcopy(before)
        for name in ('experiments','revisions','runs','events','artifacts'):
            after['jobs']['tables'][name]['row_hashes'].append(hashlib.sha256(('new-'+name).encode()).hexdigest())
            after['jobs']['tables'][name]['rows']+=1
        after['jobs']['tables']['idempotency']['row_hashes']=[]
        after['auth']['tables']['sessions']['sha256']='0'*64
        after['jobs']['sequence']={'experiments':2,'events':2,'runs':2}
        return before,after

    @contextmanager
    def smoke(self,values=None):
        with fake_upgrade() as mocks:
            mocks['_journal'].side_effect=None;mocks['_journal'].return_value={**journal(),'status':'complete'}
            mocks['_databases'].side_effect=self.snapshots()
            with patch.object(operation,'_api',side_effect=self.api_values() if values is None else values) as api:
                yield mocks,api

    def test_fixed_online_smoke_checks_exact_free_motion_and_downloaded_artifact(self):
        with self.smoke() as (mocks,api):
            result=operation.run(config(),'smoke-application')
            self.assertEqual(result['status'],'success',result)
            self.assertEqual(result['preservation_scope'],'committed_upgrade')
            self.assertEqual(result['smoke_preservation_scope'],'immutable_jobs_cohort')
            self.assertTrue(result['existing_rows_preserved']);self.assertTrue(result['scientific_smoke_verified'])
            self.assertEqual(operation.sanitize_report(operation._encoded(result)),result)
            self.assertEqual(api.call_count,7)
            submit=api.call_args_list[2]
            self.assertEqual(submit.args,(config(),'POST','/v1/runs',TOKEN,{'revision_id':self.REVISION}))
            self.assertEqual(submit.kwargs,{'key':'application-smoke-'+REQUEST_ID})
            self.assertEqual(api.call_args_list[-1],call(config(),'GET','/v1/artifacts/'+self.ARTIFACT,TOKEN,
                maximum=32*1024**2,raw_response=True))
            self.assertEqual(mocks['_databases'].call_args_list,
                [call(include_rows=True),call(include_rows=True,require_idle=False)])
            for name in ('_quiet','_stage','_build','_replace','_restore'):mocks[name].assert_not_called()

    def test_smoke_refuses_wrong_physics_contract_status_state_or_artifact(self):
        for mutation in ('position','contract','physical_claim','numerical','partial','final_state','artifact_bytes','cancelled'):
            values=self.api_values();result=values[4][1]
            if mutation=='position':result['steps'][0]['payload']['legs'][0]['sampled_frames'][4]['positions_m'][0][0]+=.00001
            elif mutation=='contract':result['schema_version']='0.2.0'
            elif mutation=='physical_claim':result['physical_validation_status']='validated'
            elif mutation=='numerical':result['steps'][0]['numerical_status']='fail'
            elif mutation=='partial':result['steps'][0]['payload']['partial']=True
            elif mutation=='final_state':result['states'][0]['data']['system']['particles'][0]['position_m']=[0,0,0]
            elif mutation=='artifact_bytes':values[-1]=(200,b'foreign artifact')
            else:values[3]=(200,{'execution_status':'CANCELLED'})
            with self.subTest(mutation=mutation),self.smoke(values) as (mocks,api):
                report=operation.run(config(),'smoke-application')
                self.assertEqual(report['status'],'failed')
                for flag in ('scientific_smoke_verified','existing_rows_preserved','new_calculation_verified'):
                    self.assertFalse(report[flag],flag)
                mocks['_restore'].assert_not_called()

    def test_smoke_refuses_busy_work_before_adding_or_cancelling_runs(self):
        with self.smoke() as (mocks,api):
            mocks['_databases'].side_effect=operation.UpgradeError()
            report=operation.run(config(),'smoke-application')
            self.assertEqual(report['status'],'failed');api.assert_not_called()
            for name in ('_quiet','_restore','_replace'):mocks[name].assert_not_called()


class FileAndArchiveTests(unittest.TestCase):
    def test_private_reader_refuses_symlink_hardlink_and_loose_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'private';p.write_bytes(b'private');p.chmod(0o600)
            self.assertEqual(operation._file(p,uid=os.geteuid()),b'private')
            link=Path(directory)/'link';link.symlink_to(p)
            with self.assertRaises(operation.UpgradeError):operation._file(link,uid=os.geteuid())
            link.unlink();os.link(p,link)
            with self.assertRaises(operation.UpgradeError):operation._file(p,uid=os.geteuid())
            link.unlink();p.chmod(0o644)
            with self.assertRaises(operation.UpgradeError):operation._file(p,uid=os.geteuid())

    def test_atomic_replace_uses_expected_bytes_and_preserves_mode(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(operation,'_parents'):
            p=Path(directory)/'private';p.write_bytes(b'old');p.chmod(0o600)
            original=operation._file
            with patch.object(operation,'_file',side_effect=lambda path,**kwargs:original(path,uid=os.geteuid(),**kwargs)):
                operation._replace(p,b'new',b'old')
                self.assertEqual(p.read_bytes(),b'new');self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600)
                with self.assertRaises(operation.UpgradeError):operation._replace(p,b'foreign',b'old')

    def archive(self,entries):
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w:') as archive:
            root=tarfile.TarInfo('quanta-'+SHA);root.type=tarfile.DIRTYPE;archive.addfile(root)
            for name,kind,raw in entries:
                info=tarfile.TarInfo(name);info.type=kind
                if kind==tarfile.REGTYPE:info.size=len(raw);archive.addfile(info,io.BytesIO(raw))
                else:info.linkname='/private';archive.addfile(info)
        return gzip.compress(stream.getvalue())

    def test_bounded_regular_archive_matches_only_selected_commit(self):
        raw=self.archive([('quanta-'+SHA+'/README.md',tarfile.REGTYPE,b'hello')])
        archive,members=operation._archive(raw,SHA)
        try:self.assertEqual(archive.extractfile(members[1][1]).read(),b'hello')
        finally:archive.close()

    def test_archive_rejects_escape_links_duplicates_wrong_commit_and_trailer(self):
        for name,kind in [('../escape',tarfile.REGTYPE),('quanta-'+SHA+'/../escape',tarfile.REGTYPE),
                ('quanta-'+SHA+'/link',tarfile.SYMTYPE),('quanta-'+SHA+'/link',tarfile.LNKTYPE),
                ('quanta-'+OLD_SOURCE+'/README.md',tarfile.REGTYPE)]:
            with self.subTest(name=name),self.assertRaises(operation.UpgradeError):operation._archive(self.archive([(name,kind,b'x')]),SHA)
        entry=('quanta-'+SHA+'/same',tarfile.REGTYPE,b'x')
        with self.assertRaises(operation.UpgradeError):operation._archive(self.archive([entry,entry]),SHA)
        with self.assertRaises(operation.UpgradeError):operation._archive(self.archive([entry])+b'trailer',SHA)

    def test_archive_expansion_is_bounded(self):
        raw=self.archive([('quanta-'+SHA+'/data',tarfile.REGTYPE,b'x'*100)])
        with patch.object(operation,'MAX_EXPANDED',128),self.assertRaises(operation.UpgradeError):operation._archive(raw,SHA)


class MailPreservationTests(unittest.TestCase):
    @contextmanager
    def files(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            raws={'gmail-smtp.json':b'{"synthetic-secret":"never-publish"}',
                  'gmail-budget.json':b'{"used":2}', 'gmail-mail.lock':b''}
            for name,raw in raws.items():
                (root/name).write_bytes(raw);(root/name).chmod(0o600)
            original=os.lstat
            def metadata(path,*args,**kwargs):
                info=original(path,*args,**kwargs)
                if str(path).startswith(str(root)):
                    values=list(info);values[4]=values[5]=10001;return os.stat_result(values)
                return info
            with patch.object(operation,'DATA',root),patch.object(operation.os,'lstat',side_effect=metadata):
                yield root,raws

    def test_three_mail_files_have_private_byte_and_metadata_fingerprints(self):
        with self.files() as (root,raws):
            before=operation._mail_settings()
            self.assertEqual(set(before),set(MAIL_FILES))
            for name,raw in raws.items():
                self.assertTrue(before[name]['present'])
                self.assertEqual(before[name]['sha256'],hashlib.sha256(raw).hexdigest())
                self.assertEqual((before[name]['uid'],before[name]['gid'],before[name]['mode']),(10001,10001,0o600))
                if raw:self.assertNotIn(raw.decode(),json.dumps(before))
            (root/'gmail-smtp.json').write_bytes(b'changed-private-settings')
            self.assertNotEqual(before,operation._mail_settings())

    def test_optional_file_presence_changes_are_part_of_preservation(self):
        with self.files() as (root,_):
            before=operation._mail_settings();(root/'gmail-budget.json').unlink()
            after=operation._mail_settings()
            self.assertFalse(after['gmail-budget.json']['present']);self.assertNotEqual(before,after)

    def test_loose_mode_links_and_shared_inode_are_not_private_settings(self):
        with self.files() as (root,_):
            p=root/'gmail-smtp.json';p.chmod(0o644)
            with self.assertRaises(operation.UpgradeError):operation._mail_settings()
            p.chmod(0o600);q=root/'saved-smtp';p.rename(q);p.symlink_to(q)
            with self.assertRaises(operation.UpgradeError):operation._mail_settings()
            p.unlink();os.link(q,p)
            with self.assertRaises(operation.UpgradeError):operation._mail_settings()


class PrivateJournalTests(unittest.TestCase):
    @contextmanager
    def sandbox(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);original_lstat,original_fstat=os.lstat,os.fstat
            def rootlike(value):
                fields=list(value);fields[4]=fields[5]=0;return os.stat_result(fields)
            with patch.object(operation,'ETC',root),patch.object(operation,'JOURNAL',root/'application-upgrade-0.16.json'),patch.object(operation,'JOURNAL_STAGING',root/'.application-upgrade-0.16.publish'),patch.object(operation,'_parents'),patch.object(os,'lstat',lambda path,*a,**kw:rootlike(original_lstat(path,*a,**kw))),patch.object(os,'fstat',lambda fd:rootlike(original_fstat(fd))):
                yield root

    def test_journal_publication_is_complete_private_and_no_replace(self):
        with self.sandbox():
            value=journal();operation._write_journal(value)
            self.assertEqual(operation._journal(),value)
            self.assertFalse(operation.JOURNAL_STAGING.exists());self.assertEqual(operation.JOURNAL.stat().st_nlink,1)
            self.assertEqual(stat.S_IMODE(operation.JOURNAL.stat().st_mode),0o600)
            with self.assertRaises(FileExistsError):operation._write_journal(journal())

    def test_old_release_journal_remains_untouched_and_is_not_new_resume_evidence(self):
        with self.sandbox() as root:
            legacy=root/'application-upgrade.json'
            raw=b'{"status":"complete","source_sha":"be398c636bbb9ba18590a7edec601bbcb5f9b1f4"}'
            legacy.write_bytes(raw);legacy.chmod(0o600)
            with self.assertRaises(FileNotFoundError):operation._journal()
            operation._write_journal(journal())
            self.assertEqual(legacy.read_bytes(),raw)
            self.assertNotEqual(operation.JOURNAL,legacy)
            self.assertEqual(operation._journal()['source_sha'],SHA)

    def test_new_watchdog_script_does_not_replace_old_release_script(self):
        with self.sandbox() as root:
            legacy=root/'application-rollback.py';legacy.write_bytes(b'legacy fixed watchdog');legacy.chmod(0o600)
            current=root/'application-rollback-0.16.py'
            with patch.object(operation,'ROLLBACK_SCRIPT',current), \
                    patch.object(operation,'_unit',return_value={'LoadState':'not-found','ActiveState':'inactive'}), \
                    patch.object(operation,'_quiet') as quiet:
                operation._arm_watchdog()
            self.assertEqual(legacy.read_bytes(),b'legacy fixed watchdog')
            self.assertEqual(current.read_bytes(),operation._watchdog_source())
            self.assertIn('--unit=quanta-application-rollback-0-16',quiet.call_args.args[0])

    def test_interrupted_write_cannot_expose_partial_final_journal(self):
        with self.sandbox():
            original=os.fdopen
            class InterruptedWriter:
                def __init__(self,descriptor):self.stream=original(descriptor,'wb')
                def __enter__(self):return self
                def __exit__(self,*args):return self.stream.__exit__(*args)
                def fileno(self):return self.stream.fileno()
                def write(self,raw):self.stream.write(raw[:len(raw)//2]);self.stream.flush();raise InterruptedError('synthetic')
            with patch.object(os,'fdopen',side_effect=lambda fd,mode:InterruptedWriter(fd) if mode=='wb' else original(fd,mode)):
                with self.assertRaises(InterruptedError):operation._write_journal(journal())
            self.assertFalse(operation.JOURNAL.exists());self.assertFalse(operation.JOURNAL_STAGING.exists())

    def test_link_publication_window_accepts_only_the_exact_private_sibling(self):
        with self.sandbox() as root:
            operation.JOURNAL_STAGING.write_bytes(operation._encoded(journal()));operation.JOURNAL_STAGING.chmod(0o600)
            os.link(operation.JOURNAL_STAGING,operation.JOURNAL)
            self.assertEqual(operation._journal(),journal())
            operation._journal_status(journal(),'rolled_back');self.assertEqual(operation._journal()['status'],'rolled_back')
        with self.sandbox() as root:
            operation.JOURNAL.write_bytes(operation._encoded(journal()));operation.JOURNAL.chmod(0o600)
            os.link(operation.JOURNAL,root/'unrelated')
            with self.assertRaises((FileNotFoundError,operation.UpgradeError)):operation._journal()

    def test_restore_refuses_operator_changes_without_overwriting(self):
        with patch.object(operation,'_file',return_value=b'foreign'),patch.object(operation,'_quiet') as quiet,patch.object(operation,'_replace') as replace:
            with self.assertRaises(operation.UpgradeError):operation._restore(journal())
            quiet.assert_not_called();replace.assert_not_called()


class WatchdogExecutionTests(unittest.TestCase):
    @contextmanager
    def sandbox(self,*,state='switching',have_journal=True,foreign=False):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);saved=journal();saved['status']=state
            settings_file=root/'settings.fixture';settings_file.write_bytes(b'private-fixed-settings');settings_file.chmod(0o600)
            saved['settings']={str(settings_file):hashlib.sha256(settings_file.read_bytes()).hexdigest()}
            journal_path=root/'application-upgrade.json';lock=root/'application.lock'
            lock.write_bytes(b'');lock.chmod(0o600)
            if have_journal:journal_path.write_bytes(operation._encoded(saved));journal_path.chmod(0o600)
            for name in ('deployment','installed'):
                p=root/(name+'.json')
                p.write_bytes(b'operator-change' if foreign and name=='deployment' else base64.b64decode(saved['new_'+name]));p.chmod(0o600)
            with patch.object(operation,'_expected_settings_modes',return_value={settings_file:0o600}), \
                    patch.object(operation,'JOURNAL',journal_path), \
                    patch.object(operation,'JOURNAL_STAGING',root/'.application-upgrade.publish'), \
                    patch.object(operation,'LOCK',lock):
                source=operation._watchdog_source().decode()
            original_lstat,original_fstat=Path.lstat,os.fstat
            def rootlike(info):
                fields=list(info);fields[4]=fields[5]=0
                if stat.S_ISDIR(fields[0]):fields[0]&=~0o022
                return os.stat_result(fields)
            calls=[]
            def ctl(command,**kwargs):
                self.assertEqual(command[0],'/usr/bin/systemctl');calls.append(command[1:]);return types.SimpleNamespace(returncode=0)
            with patch.object(Path,'lstat',lambda p:rootlike(original_lstat(p))),patch.object(os,'fstat',lambda fd:rootlike(original_fstat(fd))),patch.object(subprocess,'run',side_effect=ctl):
                yield root,saved,source,calls

    def test_actual_watchdog_restores_only_old_config_and_marks_rollback(self):
        with self.sandbox() as (root,saved,source,calls):
            exec(compile(source,'<application-watchdog-sandbox>','exec'),{})
            for name in ('deployment','installed'):
                self.assertEqual((root/(name+'.json')).read_bytes(),base64.b64decode(saved['old_'+name]))
            self.assertEqual(json.loads((root/'application-upgrade.json').read_bytes())['status'],'rolled_back')
            self.assertEqual(calls,[['stop',operation.APP],['start',operation.APP,operation.HTTPS,operation.TIMER]])

    def test_completed_watchdog_resumes_admission_without_changing_new_installation(self):
        with self.sandbox(state='complete') as (root,saved,source,calls):
            before=(root/'deployment.json').read_bytes();exec(compile(source,'<application-watchdog-sandbox>','exec'),{})
            self.assertEqual(calls,[['start',operation.APP,operation.HTTPS,operation.TIMER]])
            self.assertEqual((root/'deployment.json').read_bytes(),before)

    def test_watchdog_without_published_journal_only_resumes_fixed_services(self):
        with self.sandbox(have_journal=False) as (root,saved,source,calls):
            before=(root/'deployment.json').read_bytes()
            with self.assertRaises(SystemExit) as stopped:exec(compile(source,'<application-watchdog-sandbox>','exec'),{})
            self.assertEqual(stopped.exception.code,0)
            self.assertEqual(calls,[['start',operation.APP,operation.HTTPS,operation.TIMER]])
            self.assertEqual((root/'deployment.json').read_bytes(),before)

    def test_watchdog_cannot_overwrite_operator_config_change(self):
        with self.sandbox(foreign=True) as (root,saved,source,calls):
            with self.assertRaises(ValueError):exec(compile(source,'<application-watchdog-sandbox>','exec'),{})
            self.assertEqual(calls,[]);self.assertEqual((root/'deployment.json').read_bytes(),b'operator-change')

    def test_completed_watchdog_refuses_foreign_current_configuration(self):
        with self.sandbox(state='complete',foreign=True) as (root,saved,source,calls):
            with self.assertRaises(ValueError):exec(compile(source,'<application-watchdog-sandbox>','exec'),{})
            self.assertEqual(calls,[]);self.assertEqual((root/'deployment.json').read_bytes(),b'operator-change')

    def test_completed_watchdog_cannot_resume_changed_private_settings(self):
        with self.sandbox(state='complete') as (root,saved,source,calls):
            (root/'settings.fixture').write_bytes(b'operator-setting-change')
            with self.assertRaises(ValueError):exec(compile(source,'<application-watchdog-sandbox>','exec'),{})
            self.assertEqual(calls,[])

    def test_watchdog_handles_exact_link_publication_window(self):
        with self.sandbox() as (root,saved,source,calls):
            os.link(root/'application-upgrade.json',root/'.application-upgrade.publish')
            exec(compile(source,'<application-watchdog-sandbox>','exec'),{})
            self.assertEqual(json.loads((root/'application-upgrade.json').read_bytes())['status'],'rolled_back')


if __name__=='__main__':unittest.main()
