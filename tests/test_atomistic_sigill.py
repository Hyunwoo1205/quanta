"""Signal classification, ELF identity and fixed-operation boundaries."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


trace = load('tracer', 'scripts/trace_cp2k_sigill.py')
remote = load('remote', 'deploy/oci/remote_atomistic_probe.py')


def archived(paths):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:gz', format=tarfile.USTAR_FORMAT) as archive:
        for path in sorted(paths):
            member = tarfile.TarInfo(path)
            member.size = 1
            archive.addfile(member, io.BytesIO(b'x'))
    data = stream.getvalue()
    return data, hashlib.sha256(data).hexdigest()


class TraceTests(unittest.TestCase):
    def test_only_trace_operation_accepts_its_wrapper(self):
        base = archived(remote.REQUIRED)
        bundle = archived(remote.REQUIRED | {remote.TRACE_SCRIPT})
        self.assertEqual(set(remote.archive_files(*base)), remote.REQUIRED)
        self.assertEqual(set(remote.archive_files(*bundle, trace=True)), remote.REQUIRED | {remote.TRACE_SCRIPT})
        with self.assertRaises(remote.ProbeError):
            remote.archive_files(*bundle)
        with self.assertRaises(remote.ProbeError):
            remote.archive_files(*base, trace=True)

    def test_receipt_never_accepts_unvalidated_instruction_bytes(self):
        row = {'schema_version': 1, 'engine_sha256': trace.ENGINE_SHA256, 'input_sha256': trace.INPUT_SHA256,
               'status': 'sigill_captured', 'signal': 'SIGILL', 'synchronous': True, 'si_code': 1,
               'instruction_bytes': '00000000', 'opcode_little_endian': '0x00000000',
               'pc_matches_signal_address': True, 'module': None}
        self.assertIs(trace.validated_report(row), row)
        self.assertIsNone(trace.validated_report(dict(row, opcode_little_endian='0xd503201f')))
        self.assertIsNone(trace.validated_report(dict(row, raw_process_maps='private')))

    def test_real_synchronous_and_sent_signals(self):
        machine = platform.machine()
        if machine not in trace.ELF_MACHINE:
            self.skipTest('requires a native x86_64 or aarch64 host')
        instruction = 'ud2; nop; nop' if machine == 'x86_64' else '.inst 0'
        expected = '0f0b9090' if machine == 'x86_64' else '00000000'
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory) / 'case'
            source = f'#include <signal.h>\nint main(int n, char **v) {{ if (n > 1) raise(SIGILL); __asm__ volatile("{instruction}"); }}\n'
            subprocess.run(['gcc', '-g', '-x', 'c', '-', '-o', str(case)], input=source.encode(), check=True)
            with mock.patch.object(trace, 'MODULE_PATH', re.compile(re.escape(str(case)))):
                found = trace.trace([str(case)], machine, 4)
                if found['status'] == 'trace_denied' and not os.environ.get('QUANTA_REQUIRE_NATIVE_PTRACE'):
                    self.skipTest(f'host policy denies unprivileged ptrace with errno={found["errno"]}')
                self.assertEqual(found['status'], 'sigill_captured', found)
                self.assertTrue(found['pc_matches_signal_address'])
                self.assertEqual(found['instruction_bytes'], expected)
                self.assertEqual(found['module']['path'], str(case))
                self.assertTrue(found['module']['file_bytes_equal'])
                notes = subprocess.check_output(['readelf', '-n', str(case)], text=True)
                self.assertIn('Build ID: ' + found['module']['elf_build_id'], notes)
                sent = trace.trace([str(case), 'raise'], machine, 4)
                self.assertEqual(sent['status'], 'sigill_sent', sent)
                self.assertLessEqual(sent['si_code'], 0)
                self.assertNotIn('instruction_bytes', sent)


if __name__ == '__main__':
    unittest.main()
