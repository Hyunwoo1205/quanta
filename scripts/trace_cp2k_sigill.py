#!/usr/bin/env python3
"""Capture SIGILL in the fixed old CP2K He-D case, from its unprivileged parent."""
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import signal
import struct
import sys
import time


ENGINE = Path('/opt/cp2k/install/bin/cp2k.psmp')
ENGINE_COMMAND = Path('/opt/cp2k/install/bin/cp2k')
ENGINE_SHA256 = 'aa8cb64079e94aac831588d359c7e7c008a693701de6e3bcdd58491f850ceb7c'
INPUT = Path('/quanta-input/input.inp')
INPUT_SHA256 = '6c91137086d77321edc954e4f316a2a837078b088260f7b3ae00c73691df8bc8'
TRACE_REPORT = Path('/work/trace-sigill.json')
PTRACE_TRACEME, PTRACE_PEEKTEXT, PTRACE_CONT = 0, 1, 7
PTRACE_SETOPTIONS = 0x4200
PTRACE_GETEVENTMSG = 0x4201
PTRACE_GETSIGINFO = 0x4202
PTRACE_GETREGSET = 0x4204
PTRACE_OPTIONS = 0x100000 | 0x0E  # EXITKILL, TRACEFORK, TRACEVFORK, TRACECLONE
WALL = 0x40000000
NT_PRSTATUS = 1
ELF_MACHINE = {'aarch64': 183, 'x86_64': 62}
PC_WORD_INDEX = {'aarch64': 32, 'x86_64': 16}
MAP_LINE = re.compile(r'^([a-f0-9]+)-([a-f0-9]+) (\S+) ([a-f0-9]+) ([a-f0-9]+):([a-f0-9]+) (\d+) +(.*)$')
MODULE_PATH = re.compile(r'^/(?:opt/cp2k|usr/lib|lib)/[A-Za-z0-9_.+/-]{1,400}$')


class IoVec(ctypes.Structure):
    _fields_ = [('base', ctypes.c_void_p), ('length', ctypes.c_size_t)]


def ptrace(request, pid=0, address=0, data=0):
    call = ctypes.CDLL(None, use_errno=True).ptrace
    call.argtypes = (ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
    call.restype = ctypes.c_long
    ctypes.set_errno(0)
    result = call(request, pid, address, data)
    error = ctypes.get_errno()
    if result == -1 and error:
        raise OSError(error, os.strerror(error))
    return result


def read_exact(fd, offset, size):
    if not 0 <= offset <= 1 << 40 or not 0 <= size <= 1024 * 1024:
        raise ValueError('ELF read outside bounds')
    data = os.pread(fd, size, offset)
    if len(data) != size:
        raise ValueError('ELF read truncated')
    return data


def elf_identity(fd, machine, file_offset):
    header = read_exact(fd, 0, 64)
    if header[:7] != b'\x7fELF\x02\x01\x01':
        raise ValueError('Expected little-endian ELF64')
    if struct.unpack_from('<H', header, 18)[0] != ELF_MACHINE[machine]:
        raise ValueError('ELF machine mismatch')
    phoff = struct.unpack_from('<Q', header, 32)[0]
    phentsize, phnum = struct.unpack_from('<HH', header, 54)
    if phentsize != 56 or not 1 <= phnum <= 512:
        raise ValueError('Invalid ELF program headers')
    table = read_exact(fd, phoff, phnum * phentsize)
    load = None
    build_id = None
    for ph_type, flags, offset, vaddr, _, file_size, _, _ in struct.iter_unpack('<IIQQQQQQ', table):
        if ph_type == 1 and flags & 1 and offset <= file_offset < offset + file_size:
            if load is not None:
                raise ValueError('Ambiguous executable ELF segment')
            load = vaddr + file_offset - offset
        if ph_type == 4 and 12 <= file_size <= 1024 * 1024 and build_id is None:
            notes = read_exact(fd, offset, file_size)
            cursor = 0
            while cursor + 12 <= len(notes):
                name_size, desc_size, note_type = struct.unpack_from('<III', notes, cursor)
                start = cursor + 12
                desc = start + ((name_size + 3) & ~3)
                cursor = desc + ((desc_size + 3) & ~3)
                if cursor > len(notes):
                    break
                if note_type == 3 and 8 <= desc_size <= 64 and notes[start:start + name_size] == b'GNU\0':
                    build_id = notes[desc:desc + desc_size].hex()
                    break
    if load is None:
        raise ValueError('PC lacks an executable ELF segment')
    return {'elf_virtual_address': load, 'elf_build_id': build_id}


def mapping(pid, pc, word, machine):
    with open(f'/proc/{pid}/maps', encoding='utf-8', errors='strict') as stream:
        maps = stream.read(1024 * 1024 + 1)
    if len(maps) > 1024 * 1024:
        raise ValueError('Too many process maps')
    for line in maps.splitlines():
        match = MAP_LINE.fullmatch(line)
        if not match:
            continue
        start, end, perms, offset, major, minor, inode, path = match.groups()
        start, end = int(start, 16), int(end, 16)
        if not start <= pc <= end - len(word) or 'x' not in perms:
            continue
        if not MODULE_PATH.fullmatch(path) or not int(inode) or '..' in Path(path).parts:
            return None
        file_offset = int(offset, 16) + pc - start
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            stat = os.fstat(fd)
            if (stat.st_ino, os.major(stat.st_dev), os.minor(stat.st_dev)) != (int(inode), int(major, 16), int(minor, 16)):
                raise ValueError('Mapped ELF inode mismatch')
            if read_exact(fd, file_offset, len(word)) != word:
                raise ValueError('Mapped file opcode disagrees with live instruction')
            return {'path': path, 'file_offset': file_offset, 'file_bytes_equal': True,
                    **elf_identity(fd, machine, file_offset)}
        finally:
            os.close(fd)
    return None


def capture_sigill(pid, machine):
    info = ctypes.create_string_buffer(128)
    ptrace(PTRACE_GETSIGINFO, pid, data=ctypes.addressof(info))
    signo, _, code = struct.unpack_from('=iii', info)
    if signo != signal.SIGILL:
        raise ValueError('Unexpected SIGILL stop')
    if code <= 0:
        return {'signal': 'SIGILL', 'si_code': code, 'synchronous': False}
    regs = ctypes.create_string_buffer(512)
    iov = IoVec(ctypes.addressof(regs), ctypes.sizeof(regs))
    ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, ctypes.addressof(iov))
    offset = PC_WORD_INDEX[machine] * 8
    if iov.length < offset + 8:
        raise ValueError('Register buffer does not include PC')
    pc = struct.unpack_from('=Q', regs, offset)[0]
    if not pc or machine == 'aarch64' and pc % 4:
        raise ValueError('Invalid fault PC')
    read_pc = pc & ~7 if machine == 'aarch64' else pc
    start = pc - read_pc
    word = (ptrace(PTRACE_PEEKTEXT, pid, read_pc) & ((1 << 64) - 1)).to_bytes(8, 'little')[start:start + 4]
    result = {'signal': 'SIGILL', 'si_code': code, 'synchronous': True,
              'pc_matches_signal_address': pc == struct.unpack_from('=Q', info, 16)[0],
              'instruction_bytes': word.hex(), 'opcode_little_endian': f'0x{int.from_bytes(word, "little"):08x}'}
    try:
        result['module'] = mapping(pid, pc, word, machine)
    except (OSError, ValueError):
        result['module'] = None
    return result


def trace(argv, machine, timeout):
    read_fd, write_fd = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        pid = os.fork()
    except BaseException:
        os.close(read_fd)
        os.close(write_fd)
        raise
    if pid == 0:
        os.close(read_fd)
        try:
            ptrace(PTRACE_TRACEME)
        except OSError as exc:
            os.write(write_fd, f'trace:{exc.errno}'.encode('ascii'))
            os._exit(125)
        try:
            os.execv(argv[0], argv)
        except OSError as exc:
            os.write(write_fd, f'exec:{exc.errno}'.encode('ascii'))
            os._exit(126)

    os.close(write_fd)
    live = {pid}
    stopped_at_exec = False
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            child, status = os.waitpid(-1, os.WNOHANG | WALL)
            if not child:
                time.sleep(0.01)
                continue
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                live.discard(child)
                if child == pid:
                    failure = os.read(read_fd, 48)
                    if match := re.fullmatch(rb'(trace|exec):(\d{1,4})', failure):
                        stage, error = match.groups()
                        error = int(error)
                        kind = 'trace_denied' if stage == b'trace' and error in (errno.EPERM, errno.EACCES) else 'trace_setup_error'
                        return {'status': kind, 'errno': error}
                    return {'status': 'child_exited', 'returncode': os.waitstatus_to_exitcode(status)}
                continue
            live.add(child)
            stop = os.WSTOPSIG(status)
            event = status >> 16
            if not stopped_at_exec:
                if child != pid or stop != signal.SIGTRAP or event:
                    return {'status': 'unexpected_exec_stop'}
                ptrace(PTRACE_SETOPTIONS, pid, data=PTRACE_OPTIONS)
                stopped_at_exec = True
                stop = 0
            elif event in (1, 2, 3):
                new_pid = ctypes.c_ulong()
                ptrace(PTRACE_GETEVENTMSG, child, data=ctypes.addressof(new_pid))
                live.add(new_pid.value)
                stop = 0
            elif stop == signal.SIGILL:
                evidence = capture_sigill(child, machine)
                if evidence['synchronous']:
                    return {'status': 'sigill_captured', **evidence}
                # Do not mistake an application-sent SIGILL for an unsupported opcode.
                return {'status': 'sigill_sent', **evidence}
            elif stop == signal.SIGSTOP:
                # A traced clone/fork's initial stop is synthetic.
                stop = 0
            ptrace(PTRACE_CONT, child, data=stop)
        return {'status': 'trace_timeout'}
    finally:
        os.close(read_fd)
        for child in live:
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
        while True:
            try:
                child, status = os.waitpid(-1, WALL)
                if os.WIFSTOPPED(status):
                    os.kill(child, signal.SIGKILL)
            except ChildProcessError:
                break
            except ProcessLookupError:
                continue


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def validated_report(row):
    """Keep only the fixed diagnostic fields across the container boundary."""
    if not isinstance(row, dict):
        return None
    base = {'schema_version', 'engine_sha256', 'input_sha256', 'status'}
    if (row.get('schema_version') != 1 or row.get('engine_sha256') != ENGINE_SHA256
            or row.get('input_sha256') != INPUT_SHA256):
        return None
    status = row.get('status')
    if status == 'sigill_captured':
        fields = {'signal', 'si_code', 'synchronous', 'pc_matches_signal_address',
                  'instruction_bytes', 'opcode_little_endian', 'module'}
        if (set(row) != base | fields or row['signal'] != 'SIGILL' or row['synchronous'] is not True
                or type(row['pc_matches_signal_address']) is not bool or type(row['si_code']) is not int
                or not 0 < row['si_code'] <= 128 or not isinstance(row['instruction_bytes'], str)
                or not re.fullmatch('[a-f0-9]{8}', row['instruction_bytes'])
                or row['opcode_little_endian'] != f'0x{int.from_bytes(bytes.fromhex(row["instruction_bytes"]), "little"):08x}'):
            return None
        module = row['module']
        if module is not None and (not isinstance(module, dict)
                or set(module) != {'path', 'file_offset', 'file_bytes_equal', 'elf_virtual_address', 'elf_build_id'}
                or not isinstance(module['path'], str) or not MODULE_PATH.fullmatch(module['path'])
                or '..' in Path(module['path']).parts or module['file_bytes_equal'] is not True
                or any(type(module[key]) is not int or not 0 <= module[key] <= 1 << 40
                       for key in ('file_offset', 'elf_virtual_address'))
                or (module['elf_build_id'] is not None and (not isinstance(module['elf_build_id'], str)
                    or not re.fullmatch('(?:[a-f0-9]{2}){8,64}', module['elf_build_id'])))):
            return None
    elif status == 'sigill_sent':
        if (set(row) != base | {'signal', 'si_code', 'synchronous'} or row['signal'] != 'SIGILL'
                or row['synchronous'] is not False or type(row['si_code']) is not int or row['si_code'] > 0):
            return None
    elif status == 'child_exited':
        if set(row) != base | {'returncode'} or type(row['returncode']) is not int or not -127 <= row['returncode'] <= 255:
            return None
    elif status in ('trace_denied', 'trace_setup_error') and 'errno' in row:
        if (set(row) != base | {'errno'} or type(row['errno']) is not int or not 1 <= row['errno'] <= 4095
                or status == 'trace_denied' and row['errno'] not in (errno.EPERM, errno.EACCES)):
            return None
    elif status not in ('fixture_identity_mismatch', 'unexpected_exec_stop', 'trace_timeout', 'trace_setup_error') or set(row) != base:
        return None
    return row


def main():
    if len(sys.argv) != 1 or os.getuid() == 0 or platform.machine() != 'aarch64':
        return 2
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if ENGINE_COMMAND.resolve() != ENGINE or digest(ENGINE) != ENGINE_SHA256 or digest(INPUT) != INPUT_SHA256:
        result = {'status': 'fixture_identity_mismatch'}
    else:
        try:
            result = trace([str(ENGINE_COMMAND), '-i', str(INPUT)], 'aarch64', 90)
        except (OSError, ValueError, struct.error):
            result = {'status': 'trace_setup_error'}
    with TRACE_REPORT.open('x', encoding='ascii') as stream:
        json.dump({'schema_version': 1, 'engine_sha256': ENGINE_SHA256, 'input_sha256': INPUT_SHA256,
                   **result}, stream, sort_keys=True, separators=(',', ':'))
    return 0 if result['status'] == 'sigill_captured' else 2


if __name__ == '__main__':
    raise SystemExit(main())
