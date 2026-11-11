"""Windows backend for the Custodian platform seam (stdlib + ctypes only).

Layout: `_api()` lazily loads kernel32/advapi32 (never at import, so this module
imports on Linux/macOS); `_Win` is the only place that performs raw OS calls;
everything else is plain logic over adapter results so it is testable with a
fake adapter (tests replace the module attribute `_WIN`).
"""
from collections import namedtuple
from contextlib import contextmanager
import ctypes
import errno
from fnmatch import fnmatchcase
import hashlib
import os
from pathlib import Path
import signal
import stat
import struct
import sys
import time

NAME = 'windows'
IS_WINDOWS = True

# Budgets: copied verbatim from custodian/policy.py (POSIX walker).
MAX_ENTRIES = 20000
MAX_SECONDS = 5.0
MAX_DEPTH = 64
MAX_TOTAL_BYTES = 64 * 1024 * 1024

MAX_ACES = 256              # larger DACLs are reported as unavailable, never parsed
MAX_EXPOSED = 16            # principals listed per file
MAX_NAME_LOOKUPS = 32       # distinct LookupAccountSidW calls per snapshot
MAX_NAME_CHARS = 256
MAX_SID_CHARS = 184
PRIVATE_MODE, READABLE_MODE, WRITABLE_MODE = 0o600, 0o644, 0o666

FILE_ATTRIBUTE_REPARSE_POINT = 0x400
GENERIC_READ, GENERIC_WRITE = 0x80000000, 0x40000000
GENERIC_EXECUTE, GENERIC_ALL = 0x20000000, 0x10000000
FILE_ALL_ACCESS = 0x1F01FF
_GENERIC_MAP = ((GENERIC_ALL, FILE_ALL_ACCESS), (GENERIC_READ, 0x120089),
                (GENERIC_WRITE, 0x120116), (GENERIC_EXECUTE, 0x1200A0))
READ_MASK = 0x1             # FILE_READ_DATA / FILE_LIST_DIRECTORY
# write/append data, delete child, DELETE, WRITE_DAC, WRITE_OWNER
WRITE_MASK = 0x2 | 0x4 | 0x40 | 0x10000 | 0x40000 | 0x80000
# Rights that let a principal replace a directory on the state path. Plain
# "create folder" on a drive root (the stock Authenticated Users ACE on C:\) is
# not included: pre-created components are caught by the owner checks instead.
DIR_REPLACE_MASK = 0x40 | 0x10000 | 0x40000 | 0x80000

SID_EVERYONE = 'S-1-1-0'
SID_AUTHENTICATED_USERS = 'S-1-5-11'
SID_USERS = 'S-1-5-32-545'
SID_SYSTEM = 'S-1-5-18'
SID_ADMINISTRATORS = 'S-1-5-32-544'
SID_CREATOR_OWNER = 'S-1-3-0'
SID_OWNER_RIGHTS = 'S-1-3-4'
SID_TRUSTED_INSTALLER = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
# Fixed English names for well-known SIDs: deterministic, never localised.
WELL_KNOWN = {SID_EVERYONE: 'Everyone', SID_AUTHENTICATED_USERS: 'Authenticated Users',
              SID_USERS: 'BUILTIN\\Users', 'S-1-5-32-546': 'BUILTIN\\Guests',
              'S-1-5-7': 'Anonymous Logon', 'S-1-5-4': 'Interactive',
              SID_SYSTEM: 'SYSTEM', SID_ADMINISTRATORS: 'BUILTIN\\Administrators'}
BROAD_SIDS = (SID_EVERYONE, SID_AUTHENTICATED_USERS, SID_USERS, 'S-1-5-32-546', 'S-1-5-7', 'S-1-5-4')
BROAD_NAMES = frozenset(WELL_KNOWN[sid] for sid in BROAD_SIDS)

STATE_FILES = ('settings.json', 'state.sqlite3', 'monitor.json', 'monitor.lock', 'scan.lock',
               'dashboard-login.json',
               'state.sqlite3-journal', 'state.sqlite3-wal', 'state.sqlite3-shm')
_STATE_FILE_ERROR = 'State files must be current-user regular files without hard links'
_NOT_DIRECTORY_ERROR = 'state_dir must have only accessible nonsymlink directories'
_ACL_ERROR = 'Access control list unavailable'
_SOFT = (OSError, ValueError, ctypes.ArgumentError)
_LOCK_OFFSET = 1 << 30      # lock one byte far past any content so readers are never blocked

# Win32 constants used only by the adapter.
_SE_FILE_OBJECT = 1
_OWNER_SECURITY_INFORMATION, _DACL_SECURITY_INFORMATION = 0x1, 0x4
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_ACL_REVISION = 2
_OBJECT_INHERIT_ACE, _CONTAINER_INHERIT_ACE = 0x1, 0x2
_INHERIT_ONLY_ACE, _INHERITED_ACE = 0x08, 0x10
_ACE_KINDS = {0: 'allow', 1: 'deny', 5: 'other', 9: 'other', 11: 'other'}
_FILE_SHARE_ALL, _CREATE_NEW, _OPEN_EXISTING = 0x7, 1, 3
_FILE_ATTRIBUTE_NORMAL, _FILE_FLAG_OPEN_REPARSE_POINT = 0x80, 0x00200000
_TOKEN_QUERY, _TOKEN_USER_CLASS = 0x8, 1
_PROCESS_QUERY_LIMITED_INFORMATION, _STILL_ACTIVE = 0x1000, 259
_TOKEN_USER_BYTES, _ACL_BYTES, _NAME_CHARS = 256, 256, 257


class _BudgetExceeded(Exception):
    pass


class FileInfo(namedtuple('FileInfo', 'attributes mode dev ino nlink size mtime_ns')):
    """lstat-style facts about one entry; produced by the adapter."""
    __slots__ = ()

    @property
    def is_reparse(self):
        return bool(self.attributes & FILE_ATTRIBUTE_REPARSE_POINT) or stat.S_ISLNK(self.mode)

    @property
    def is_dir(self):
        return stat.S_ISDIR(self.mode) and not self.is_reparse

    @property
    def is_regular(self):
        return stat.S_ISREG(self.mode) and not self.is_reparse


def _file_info(result):
    return FileInfo(getattr(result, 'st_file_attributes', 0), result.st_mode, result.st_dev,
                    result.st_ino, result.st_nlink, result.st_size, result.st_mtime_ns)


class _UnicodeString(ctypes.Structure):
    _fields_ = [('Length', ctypes.c_uint16), ('MaximumLength', ctypes.c_uint16),
                ('Buffer', ctypes.c_void_p)]


class _ObjectAttributes(ctypes.Structure):
    _fields_ = [('Length', ctypes.c_uint32), ('RootDirectory', ctypes.c_void_p),
                ('ObjectName', ctypes.POINTER(_UnicodeString)), ('Attributes', ctypes.c_uint32),
                ('SecurityDescriptor', ctypes.c_void_p), ('SecurityQualityOfService', ctypes.c_void_p)]


class _IoStatusBlock(ctypes.Structure):
    _fields_ = [('Status', ctypes.c_void_p), ('Information', ctypes.c_size_t)]


def _component(name):
    if not isinstance(name, str) or not name or name in ('.', '..') or any(c in name for c in '/\\:\0'):
        raise ValueError('Unsafe child name')
    return name


def ace_label(kind):
    if kind == 0:
        return 'allow'
    if kind == 1:
        return 'deny'
    if kind in (2, 3, 7, 8, 10, 13, 14, 15, 16, 17, 18, 19, 20):
        return None  # audit, alarm, mandatory label, resource and policy ACEs
    return 'other'   # unknown access grants must fail closed


def parse_file_information(raw):
    if len(raw) < 52:
        raise OSError('Truncated file information')
    attrs = struct.unpack_from('<I', raw)[0]
    ticks = struct.unpack_from('<Q', raw, 20)[0]
    dev, high, low, links, ih, il = struct.unpack_from('<IIIIII', raw, 28)
    return FileInfo(attrs, stat.S_IFDIR if attrs & 0x10 else stat.S_IFREG,
                    dev, (ih << 32) | il, links, (high << 32) | low,
                    (ticks - 116444736000000000) * 100)


def parse_directory_names(raw):
    names, offset = [], 0
    while True:
        if offset + 104 > len(raw):
            raise OSError('Truncated directory information')
        more = struct.unpack_from('<I', raw, offset)[0]
        size = struct.unpack_from('<I', raw, offset + 60)[0]
        end = offset + 104 + size
        if size % 2 or end > len(raw) or (more and (more < 104 + size or more % 8 or offset + more >= len(raw))):
            raise OSError('Malformed directory information')
        try:
            name = raw[offset + 104:end].decode('utf-16-le')
        except UnicodeError as exc:
            raise OSError('Invalid directory name') from exc
        if name not in ('.', '..'):
            names.append(_component(name))
        if not more:
            return names
        offset += more


def _pin_directory(win, path, pins):
    path = Path(os.path.abspath(path))
    handle = win.open_path(path.anchor, 'pin')
    pins.append(handle)
    if not win.info(handle).is_dir:
        raise ValueError(_NOT_DIRECTORY_ERROR)
    for name in path.parts[1:]:
        handle = win.open_child(handle, _component(name), 'pin')
        pins.append(handle)
        if not win.info(handle).is_dir:
            raise ValueError(_NOT_DIRECTORY_ERROR)
    return handle


# ---------------------------------------------------------------- Win32 access
_API = None


def _api():
    """Load and declare the Win32 functions on first use; OSError elsewhere."""
    global _API
    if _API is None:
        if sys.platform != 'win32' or not hasattr(ctypes, 'WinDLL'):
            raise OSError('Win32 API is unavailable on this platform')
        V, D, B, W = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_wchar_p
        PV, PD = ctypes.POINTER(V), ctypes.POINTER(D)
        try:
            k = ctypes.WinDLL('kernel32', use_last_error=True)
            a = ctypes.WinDLL('advapi32', use_last_error=True)
            for library, name, restype, argtypes in (
                    (k, 'CreateFileW', V, [W, D, D, V, D, D, V]),
                    (k, 'CloseHandle', B, [V]),
                    (k, 'LocalFree', V, [V]),
                    (k, 'GetCurrentProcess', V, []),
                    (k, 'OpenProcess', V, [D, B, D]),
                    (k, 'GetExitCodeProcess', B, [V, PD]),
                    (a, 'OpenProcessToken', B, [V, D, PV]),
                    (a, 'GetTokenInformation', B, [V, D, V, D, PD]),
                    (a, 'ConvertSidToStringSidW', B, [V, PV]),
                    (a, 'ConvertStringSidToSidW', B, [W, PV]),
                    (a, 'LookupAccountSidW', B, [W, V, W, PD, W, PD, PD]),
                    (a, 'GetNamedSecurityInfoW', D, [W, D, D, PV, PV, PV, PV, PV]),
                    (a, 'GetSecurityInfo', D, [V, D, D, PV, PV, PV, PV, PV]),
                    (a, 'SetNamedSecurityInfoW', D, [W, D, D, V, V, V, V]),
                    (a, 'GetAce', B, [V, D, PV]),
                    (a, 'InitializeAcl', B, [V, D, D]),
                    (a, 'AddAccessAllowedAceEx', B, [V, D, D, D, V])):
                function = getattr(library, name)
                function.restype, function.argtypes = restype, argtypes
        except AttributeError as exc:
            raise OSError('A required Win32 function is unavailable') from exc
        _API = (k, a)
    return _API


def _last_error():
    return ctypes.WinError(ctypes.get_last_error())


class _Win:
    """Every raw OS call lives here; tests substitute a fake with the same methods."""

    def __init__(self):
        self._me = None
        self._sid_cache = {}

    def open_path(self, path, mode='pin'):
        k, _ = _api()
        handle = k.CreateFileW(str(path), 0x120081, 3, None, _OPEN_EXISTING,
                               0x02000000 | _FILE_FLAG_OPEN_REPARSE_POINT, None)
        if handle is None or handle == ctypes.c_void_p(-1).value:
            raise _last_error()
        return handle

    def _relative(self, parent, name, mode, disposition=1, write=False, private=False):
        _component(name)
        _api()
        n = ctypes.WinDLL('ntdll')
        V, D = ctypes.c_void_p, ctypes.c_uint32
        n.NtCreateFile.restype = ctypes.c_int32
        n.NtCreateFile.argtypes = [ctypes.POINTER(V), D, ctypes.POINTER(_ObjectAttributes),
                                  ctypes.POINTER(_IoStatusBlock), V, D, D, D, D, V, D]
        n.RtlNtStatusToDosError.restype = D
        n.RtlNtStatusToDosError.argtypes = [ctypes.c_int32]
        text = ctypes.create_unicode_buffer(name)
        length = len(name.encode('utf-16-le'))
        unicode = _UnicodeString(length, length + 2, ctypes.cast(text, V))
        attrs = _ObjectAttributes(ctypes.sizeof(_ObjectAttributes), parent,
                                  ctypes.pointer(unicode), 0x40, None, None)
        out, ios = V(), _IoStatusBlock()
        access = 0x120080  # SYNCHRONIZE | FILE_READ_ATTRIBUTES
        if mode in ('meta', 'read', 'file'):
            access |= 0x20000  # READ_CONTROL
        if mode in ('pin', 'dir'):
            # Data/list access makes Windows enforce sharing (including no delete).
            access |= 1
        if mode in ('read', 'file'):
            access |= 1
        if write:
            access |= 2 | 4
        if mode == 'atomic':
            access |= 2 | 4 | 0x10000 | 0x40000
        options = 0x00200000 | 0x20  # OPEN_REPARSE_POINT | SYNCHRONOUS_IO_NONALERT
        if mode in ('pin', 'dir'):
            options |= 1  # DIRECTORY_FILE
        descriptor = V()
        k, a = _api()
        if private:
            a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
                ctypes.c_wchar_p, D, ctypes.POINTER(V), ctypes.POINTER(D)]
            a.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = ctypes.c_int
            sddl = f'D:P(A;;FA;;;{self.current_user_sid()})(A;;FA;;;SY)'
            if not a.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl, 1, ctypes.byref(descriptor), None):
                raise _last_error()
            attrs.SecurityDescriptor = descriptor.value
        try:
            status = n.NtCreateFile(ctypes.byref(out), access, ctypes.byref(attrs), ctypes.byref(ios),
                                    None, 0x80, 3, disposition, options, None, 0)
        finally:
            if descriptor.value:
                k.LocalFree(descriptor)
        if status < 0:
            raise ctypes.WinError(n.RtlNtStatusToDosError(status))
        return out.value

    def open_child(self, parent, name, mode):
        return self._relative(parent, name, mode)

    def open_file(self, parent, name, *, write=False, create_new=False):
        return self._relative(parent, name, 'file', 2 if create_new else 1, write)

    def make_dir(self, parent, name):
        return self._relative(parent, name, 'pin', 2)

    def info(self, handle):
        k, _ = _api()
        k.GetFileInformationByHandle.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        k.GetFileInformationByHandle.restype = ctypes.c_int
        raw = ctypes.create_string_buffer(52)
        if not k.GetFileInformationByHandle(handle, raw):
            raise _last_error()
        return parse_file_information(raw.raw)

    def list_names(self, handle, limit):
        k, _ = _api()
        k.GetFileInformationByHandleEx.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        k.GetFileInformationByHandleEx.restype = ctypes.c_int
        names, first = [], True
        while len(names) < limit:
            raw = ctypes.create_string_buffer(65536)
            if not k.GetFileInformationByHandleEx(handle, 11 if first else 10, raw, len(raw)):
                if ctypes.get_last_error() == 18:
                    break
                raise _last_error()
            first = False
            names.extend(parse_directory_names(raw.raw)[:limit - len(names)])
        return names

    def read(self, handle, count):
        k, _ = _api()
        k.ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
                               ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
        k.ReadFile.restype = ctypes.c_int
        raw, read = ctypes.create_string_buffer(count), ctypes.c_uint32()
        if not k.ReadFile(handle, raw, count, ctypes.byref(read), None):
            raise _last_error()
        return raw.raw[:read.value]

    def create_atomic(self, parent, name):
        return self._relative(parent, name, 'atomic', 2, True, private=True)

    def write(self, handle, data):
        k, _ = _api()
        k.WriteFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
                                ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
        k.WriteFile.restype = ctypes.c_int
        written = ctypes.c_uint32()
        if not k.WriteFile(handle, data, len(data), ctypes.byref(written), None):
            raise _last_error()
        return written.value

    def flush(self, handle):
        k, _ = _api()
        k.FlushFileBuffers.argtypes = [ctypes.c_void_p]
        k.FlushFileBuffers.restype = ctypes.c_int
        if not k.FlushFileBuffers(handle):
            raise _last_error()

    def _set_information(self, handle, kind, buffer):
        k, _ = _api()
        k.SetFileInformationByHandle.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                                ctypes.c_void_p, ctypes.c_uint32]
        k.SetFileInformationByHandle.restype = ctypes.c_int
        if not k.SetFileInformationByHandle(handle, kind, ctypes.byref(buffer), ctypes.sizeof(buffer)):
            raise _last_error()

    def replace(self, handle, parent, name):
        encoded = _component(name).encode('utf-16-le')
        class Rename(ctypes.Structure):
            _fields_ = [('ReplaceIfExists', ctypes.c_ubyte), ('RootDirectory', ctypes.c_void_p),
                        ('FileNameLength', ctypes.c_uint32),
                        ('FileName', ctypes.c_uint16 * (len(encoded) // 2))]
        value = Rename()
        value.ReplaceIfExists, value.RootDirectory, value.FileNameLength = 1, parent, len(encoded)
        ctypes.memmove(ctypes.addressof(value) + Rename.FileName.offset, encoded, len(encoded))
        self._set_information(handle, 3, value)

    def discard(self, handle):
        self._set_information(handle, 4, ctypes.c_ubyte(1))

    def to_fd(self, handle, write):
        import msvcrt
        return msvcrt.open_osfhandle(handle, os.O_BINARY | os.O_NOINHERIT | (os.O_RDWR if write else os.O_RDONLY))

    def fd_handle(self, fd):
        import msvcrt
        return msvcrt.get_osfhandle(fd)

    def close_fd(self, fd):
        os.close(fd)

    def close(self, handle):
        k, _ = _api()
        k.CloseHandle(handle)

    # --- identity
    def _sid_string(self, sid):
        k, a = _api()
        text = ctypes.c_void_p()
        if not a.ConvertSidToStringSidW(sid, ctypes.byref(text)) or not text.value:
            raise _last_error()
        try:
            return ctypes.wstring_at(text.value)[:MAX_SID_CHARS]
        finally:
            k.LocalFree(text)

    def _token_user_sid(self, process):
        k, a = _api()
        token = ctypes.c_void_p()
        if not a.OpenProcessToken(process, _TOKEN_QUERY, ctypes.byref(token)):
            raise _last_error()
        try:
            buffer = ctypes.create_string_buffer(_TOKEN_USER_BYTES)
            needed = ctypes.c_uint32(0)
            if not a.GetTokenInformation(token, _TOKEN_USER_CLASS, buffer, len(buffer),
                                         ctypes.byref(needed)):
                raise _last_error()
            sid = ctypes.c_void_p.from_buffer(buffer).value   # TOKEN_USER.User.Sid
            if not sid:
                raise OSError('Token carries no user SID')
            return self._sid_string(sid)
        finally:
            k.CloseHandle(token)

    def current_user_sid(self):
        if self._me is None:
            k, _ = _api()
            self._me = self._token_user_sid(k.GetCurrentProcess())   # pseudo handle: not closed
        return self._me

    def open_process_owner_sid(self, pid):
        """User SID of a live process, or None if it has exited."""
        k, _ = _api()
        process = k.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not process:
            raise _last_error()
        try:
            code = ctypes.c_uint32(0)
            if not k.GetExitCodeProcess(process, ctypes.byref(code)):
                raise _last_error()
            if code.value != _STILL_ACTIVE:
                return None
            return self._token_user_sid(process)
        finally:
            k.CloseHandle(process)

    def lookup_sid(self, sid_text):
        k, a = _api()
        sid = ctypes.c_void_p()
        if not a.ConvertStringSidToSidW(sid_text, ctypes.byref(sid)):
            raise _last_error()
        try:
            name = ctypes.create_unicode_buffer(_NAME_CHARS)
            domain = ctypes.create_unicode_buffer(_NAME_CHARS)
            name_size, domain_size = ctypes.c_uint32(_NAME_CHARS), ctypes.c_uint32(_NAME_CHARS)
            use = ctypes.c_uint32(0)
            if not a.LookupAccountSidW(None, sid, name, ctypes.byref(name_size), domain,
                                       ctypes.byref(domain_size), ctypes.byref(use)):
                raise _last_error()
            return f'{domain.value}\\{name.value}' if domain.value else name.value
        finally:
            k.LocalFree(sid)

    # --- security descriptors
    def get_dacl_entries(self, target):
        """{'owner': sid, 'dacl': [ace, ...] | None}; None is a NULL (unrestricted) DACL.

        `target` is a retained native handle. Paths are supported for diagnostics
        and native tests only; security-sensitive callers always pass a handle.
        """
        k, a = _api()
        owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
        wanted = _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION
        refs = (ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor))
        if isinstance(target, int):
            code = a.GetSecurityInfo(target, _SE_FILE_OBJECT, wanted, *refs)
        else:
            code = a.GetNamedSecurityInfoW(target, _SE_FILE_OBJECT, wanted, *refs)
        if code:
            raise ctypes.WinError(code)
        try:
            if not owner.value:
                raise OSError('Security descriptor has no owner')
            return {'owner': self._sid_string(owner.value), 'dacl': self._read_acl(dacl.value)}
        finally:
            k.LocalFree(descriptor)

    def _read_acl(self, acl):
        if not acl:
            return None
        _, a = _api()
        count = struct.unpack('<BBHHH', ctypes.string_at(acl, 8))[3]
        if count > MAX_ACES:
            raise OSError('Access control list exceeds the supported size')
        entries = []
        for index in range(count):
            ace = ctypes.c_void_p()
            if not a.GetAce(acl, index, ctypes.byref(ace)) or not ace.value:
                raise _last_error()
            kind, flags, size = struct.unpack('<BBH', ctypes.string_at(ace.value, 4))
            if size < 8:
                raise OSError('Malformed access control entry')
            mask = struct.unpack('<I', ctypes.string_at(ace.value + 4, 4))[0]
            label = ace_label(kind)
            if label is None:       # non-access ACEs do not grant file rights
                continue
            sid = ''
            if label != 'other':
                if size < 16:
                    raise OSError('Malformed access control entry')
                sid_bytes = 8 + 4 * ctypes.string_at(ace.value + 8, 2)[1]
                if 8 + sid_bytes > size:
                    raise OSError('Malformed access control entry')
                raw = ctypes.string_at(ace.value + 8, sid_bytes)
                sid = self._sid_cache.get(raw)
                if sid is None:
                    sid = self._sid_string(ace.value + 8)
                    if len(self._sid_cache) < 512:
                        self._sid_cache[raw] = sid
            entries.append({'type': label, 'sid': sid, 'mask': mask,
                            'inherited': bool(flags & _INHERITED_ACE),
                            'inherit_only': bool(flags & _INHERIT_ONLY_ACE)})
        return entries

    def set_private_dacl(self, handle, is_dir, user_sid):
        # Manual ACL buffer (InitializeAcl + AddAccessAllowedAceEx) needs zero ctypes
        # structures; SetEntriesInAclW would need EXPLICIT_ACCESS_W and TRUSTEE_W.
        # Two ACEs with maximal SIDs need 8 + 2 * (8 + 68) = 160 bytes; 256 is fixed.
        k, a = _api()
        acl = ctypes.create_string_buffer(_ACL_BYTES)
        if not a.InitializeAcl(acl, len(acl), _ACL_REVISION):
            raise _last_error()
        flags = (_OBJECT_INHERIT_ACE | _CONTAINER_INHERIT_ACE) if is_dir else 0
        for text in (user_sid, SID_SYSTEM):
            sid = ctypes.c_void_p()
            if not a.ConvertStringSidToSidW(text, ctypes.byref(sid)):
                raise _last_error()
            try:
                if not a.AddAccessAllowedAceEx(acl, _ACL_REVISION, flags, FILE_ALL_ACCESS, sid):
                    raise _last_error()
            finally:
                k.LocalFree(sid)
        # ReOpenFile upgrades rights on the same object, never by its current name.
        # READ_CONTROL is needed when protecting/reading back the security descriptor.
        k.ReOpenFile.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
        k.ReOpenFile.restype = ctypes.c_void_p
        writable = k.ReOpenFile(handle, 0x60000, 7, 0x02000000 | _FILE_FLAG_OPEN_REPARSE_POINT)
        if writable is None or writable == ctypes.c_void_p(-1).value:
            raise _last_error()
        a.SetSecurityInfo.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                                      ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        a.SetSecurityInfo.restype = ctypes.c_uint32
        try:
            code = a.SetSecurityInfo(
            writable, _SE_FILE_OBJECT, _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION,
            None, None, acl, None)
        finally:
            k.CloseHandle(writable)
        if code:
            raise ctypes.WinError(code)

    # --- byte-range locks (msvcrt.locking: no OVERLAPPED structure needed)
    def lock_region(self, fd):
        import msvcrt
        position = os.lseek(fd, 0, os.SEEK_CUR)
        try:
            os.lseek(fd, _LOCK_OFFSET, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            return True
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EDEADLK):
                return False
            raise
        finally:
            os.lseek(fd, position, os.SEEK_SET)

    def unlock_region(self, fd):
        import msvcrt
        position = os.lseek(fd, 0, os.SEEK_CUR)
        try:
            os.lseek(fd, _LOCK_OFFSET, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        finally:
            os.lseek(fd, position, os.SEEK_SET)


_WIN = None


def _win():
    global _WIN
    if _WIN is None:
        _WIN = _Win()
    return _WIN


# ------------------------------------------------------------------ pure logic
# custodian.policy delegates bounded_snapshot to this package, so its helpers are
# imported at call time to avoid an import cycle.
def _is_sensitive(path):
    from ..policy import is_sensitive
    return is_sensitive(path)


def _clean(value):
    from ..policy import sanitise_text
    return sanitise_text(str(value))[:MAX_NAME_CHARS]


def entry_type(info):
    if info.is_reparse:
        return 'symlink'            # symlink, junction, mount point, any other reparse tag
    return 'file' if info.is_regular else 'other'


def should_descend(info, sensitive):
    return info.is_dir and not sensitive


def should_hash(info, sensitive, suffix):
    return info.is_regular and info.nlink == 1 and not sensitive and suffix.lower() in {'.py', '.md'}


def _fold(text):
    return text.replace('\\', '/').casefold()


def is_excluded(candidates, patterns):
    """Case-insensitive, separator-insensitive fnmatch of any candidate."""
    folded = [_fold(candidate) for candidate in candidates]
    return any(fnmatchcase(candidate, _fold(pattern)) for pattern in patterns for candidate in folded)


def _signature(info):
    return (info.dev, info.ino, info.nlink, info.size, info.mtime_ns, info.is_regular)


def _expand(mask):
    for generic, specific in _GENERIC_MAP:
        if mask & generic:
            mask = (mask & ~generic) | specific
    return mask & 0xFFFFFFFF


def effective_grants(dacl):
    """sid -> rights granted on the object itself, honouring earlier deny ACEs."""
    if dacl is None:
        return {SID_EVERYONE: FILE_ALL_ACCESS}
    if len(dacl) > MAX_ACES:        # never judge a truncated list: fail closed
        return {'': FILE_ALL_ACCESS}
    denied, granted = {}, {}
    for ace in dacl:
        if ace.get('inherit_only'):
            continue
        sid, mask, kind = ace.get('sid') or '', _expand(int(ace.get('mask', 0))), ace.get('type')
        if kind == 'deny':
            denied[sid] = denied.get(sid, 0) | mask
        elif kind == 'allow':
            mask &= ~(denied.get(sid, 0) | denied.get(SID_EVERYONE, 0))
            if mask:
                granted[sid] = granted.get(sid, 0) | mask
        else:                       # unparsed allow-type ACE: assume the worst
            granted[''] = FILE_ALL_ACCESS
    return granted


def classify_dacl(owner, dacl, trusted=()):
    """{'level': 'private'|'read'|'write', 'principals': [sid, ...]}.

    Owner, SYSTEM and Administrators are never an exposure; `trusted` adds the
    scanning user so their own access to an Administrators-owned file is not flagged.
    """
    safe = {SID_SYSTEM, SID_ADMINISTRATORS, SID_CREATOR_OWNER, SID_OWNER_RIGHTS, *trusted}
    if owner and owner not in BROAD_SIDS:
        safe.add(owner)
    writers, readers = [], []
    for sid, mask in effective_grants(dacl).items():
        if sid in safe:
            continue
        if mask & WRITE_MASK:
            writers.append(sid)
        elif mask & READ_MASK:
            readers.append(sid)
    level = 'write' if writers else 'read' if readers else 'private'
    return {'level': level, 'principals': writers + readers}


def synthetic_mode(level):
    return {'private': PRIVATE_MODE, 'read': READABLE_MODE, 'write': WRITABLE_MODE}[level]


def principal_name(sid, lookup=None):
    """Display name: fixed well-known name, else account lookup, else the SID string."""
    if sid in WELL_KNOWN:
        return WELL_KNOWN[sid]
    if not sid:
        return 'unrecognised access rule'
    name = ''
    if lookup is not None:
        try:
            name = _clean(lookup(sid))
        except _SOFT:
            name = ''
    return name or _clean(sid)[:MAX_SID_CHARS] or 'unknown principal'


def build_metadata(path, info, security, trusted, resolve):
    item = {'path': str(path), 'type': entry_type(info),
            'mode': 0 if info.is_reparse else PRIVATE_MODE, 'uid': '',
            'size': info.size, 'mtime_ns': info.mtime_ns}
    if security is not None and not info.is_reparse:
        verdict = classify_dacl(security['owner'], security['dacl'], trusted)
        item['uid'] = str(security['owner'])[:MAX_SID_CHARS]
        item['mode'] = synthetic_mode(verdict['level'])
        if verdict['principals']:
            item['exposed_to'] = list(dict.fromkeys(
                resolve(sid) for sid in verdict['principals'][:MAX_EXPOSED]))
    return item


def access_exposure(meta):
    """None when private to the owner; else severity/mode/exposed_to/summary."""
    try:
        mode = int(meta.get('mode', 0)) & 0o777
        listed = [_clean(name) for name in list(meta.get('exposed_to') or [])[:MAX_EXPOSED]]
        kind = meta.get('type')
    except (AttributeError, TypeError, ValueError):
        return None
    if kind == 'symlink' or not mode & 0o077:
        return None
    writable = bool(mode & 0o022)
    broad = not listed or any(name in BROAD_NAMES for name in listed)
    names = listed or ['other principals']
    return {'severity': 'high' if writable or broad else 'medium', 'mode': mode, 'exposed_to': names,
            'summary': f"sensitive file is {'writable' if writable else 'readable'} by: {', '.join(names)}"}


def state_root_violation(info, security, *, is_last, me):
    """Plain message when a directory on the state path breaks policy, else None."""
    if info.is_reparse or not info.is_dir:
        return _NOT_DIRECTORY_ERROR
    owner = security['owner']
    if is_last:
        return None if owner in (me, SID_ADMINISTRATORS) else 'state_dir owner must be the current user'
    if owner not in (me, SID_SYSTEM, SID_ADMINISTRATORS, SID_TRUSTED_INSTALLER):
        return 'state_dir ancestor owner must be the current user or root'
    grants = effective_grants(security['dacl'])
    trusted = {me, SID_SYSTEM, SID_ADMINISTRATORS, SID_TRUSTED_INSTALLER, SID_CREATOR_OWNER, SID_OWNER_RIGHTS}
    if any(mask & DIR_REPLACE_MASK for sid, mask in grants.items() if sid not in trusted):
        return 'state_dir ancestor must not be writable by other users'
    return None


# -------------------------------------------------------------------- identity
def current_principal() -> str:
    return _win().current_user_sid()


def owner_of(path_or_fd) -> str:
    win, pins = _win(), []
    if isinstance(path_or_fd, int):
        return win.get_dacl_entries(win.fd_handle(path_or_fd))['owner']
    try:
        path = Path(path_or_fd)
        parent = _pin_directory(win, path.parent, pins)
        handle = win.open_child(parent, _component(path.name), 'meta')
        pins.append(handle)
        if win.info(handle).is_reparse:
            raise ValueError('Refusing ownership through a reparse point')
        return win.get_dacl_entries(handle)['owner']
    finally:
        for handle in reversed(pins):
            win.close(handle)


def _restrict(win, handle, is_dir, me):
    try:
        win.set_private_dacl(handle, is_dir, me)
        security = win.get_dacl_entries(handle)
        if classify_dacl(security['owner'], security['dacl'], (me,))['level'] != 'private':
            raise ValueError('File must be private')
    except OSError as exc:
        raise ValueError('File must be private') from exc


def _private_file(win, handle, me, created=False, max_bytes=None):
    info, security = win.info(handle), win.get_dacl_entries(handle)
    if not info.is_regular or info.nlink != 1 or security['owner'] not in (me, SID_ADMINISTRATORS):
        raise ValueError(_STATE_FILE_ERROR)
    if max_bytes is not None and info.size > max_bytes:
        raise ValueError('File exceeds the permitted size')
    level = classify_dacl(security['owner'], security['dacl'], (me,))['level']
    if not created and level == 'write':
        raise ValueError('Existing file must be private and not writable by others')
    if created or level != 'private':
        _restrict(win, handle, False, me)


def ensure_private_dir(path: Path) -> None:
    win, pins = _win(), []
    try:
        parent = _pin_directory(win, Path(path).parent, pins)
        try:
            handle = win.open_child(parent, _component(Path(path).name), 'pin')
        except FileNotFoundError:
            try:
                handle = win.make_dir(parent, _component(Path(path).name))
            except FileExistsError:
                handle = win.open_child(parent, Path(path).name, 'pin')
        pins.append(handle)
        if not win.info(handle).is_dir:
            raise ValueError(_NOT_DIRECTORY_ERROR)
        _restrict(win, handle, True, win.current_user_sid())
    finally:
        for handle in reversed(pins):
            win.close(handle)


def ensure_private_file(path: Path) -> None:
    win, pins = _win(), []
    try:
        parent = _pin_directory(win, Path(path).parent, pins)
        handle = win.open_child(parent, _component(Path(path).name), 'meta')
        pins.append(handle)
        info = win.info(handle)
        if not info.is_regular or info.nlink != 1:
            raise ValueError(_STATE_FILE_ERROR)
        _restrict(win, handle, False, win.current_user_sid())
    finally:
        for handle in reversed(pins):
            win.close(handle)


def open_private_file(path: Path, *, write: bool, create: bool, max_bytes: int | None = None) -> int:
    win, pins = _win(), []
    handle = None
    try:
        parent = _pin_directory(win, Path(path).parent, pins)
        created = False
        if create:
            try:
                handle = win.open_file(parent, _component(Path(path).name), write=write, create_new=True)
                created = True
            except FileExistsError:
                pass
        if handle is None:
            handle = win.open_file(parent, _component(Path(path).name), write=write)
        _private_file(win, handle, win.current_user_sid(), created, max_bytes)
        fd = win.to_fd(handle, write)
        handle = None  # ownership transferred to CRT
        return fd
    finally:
        if handle is not None:
            win.close(handle)
        for pin in reversed(pins):
            win.close(pin)


def validate_state_root(path: Path) -> None:
    if '..' in Path(path).parts:
        raise ValueError('state_dir must not contain traversal components')
    root = Path(os.path.abspath(path))
    if root == Path(root.anchor) or root == Path.home():
        raise ValueError('Select a dedicated state directory, not root or home')
    win, pins = _win(), []
    me = win.current_user_sid()
    try:
        chain = [*reversed(root.parents), root]
        for index, directory in enumerate(chain):
            try:
                handle = (win.open_path(str(directory), 'pin') if not pins else
                          win.open_child(pins[-1], _component(directory.name), 'pin'))
            except FileNotFoundError:
                try:
                    handle = win.make_dir(pins[-1], _component(directory.name))
                    try:
                        _restrict(win, handle, True, me)
                    except BaseException:
                        win.close(handle)
                        raise
                except FileExistsError:
                    handle = win.open_child(pins[-1], directory.name, 'pin')
            except OSError as exc:
                raise ValueError(_NOT_DIRECTORY_ERROR) from exc
            pins.append(handle)
            problem = state_root_violation(win.info(handle), win.get_dacl_entries(handle),
                                            is_last=index == len(chain) - 1, me=me)
            if problem:
                raise ValueError(problem)
        _restrict(win, pins[-1], True, me)
        for name in STATE_FILES:
            try:
                handle = win.open_child(pins[-1], name, 'meta')
            except FileNotFoundError:
                continue
            try:
                _private_file(win, handle, me)
            finally:
                win.close(handle)
    finally:
        for handle in reversed(pins):
            win.close(handle)


def fsync_directory(path: Path) -> None:
    return None                     # NTFS offers no directory fsync through the C runtime


# --------------------------------------------------------------------- locking
def try_lock_exclusive(fd: int) -> bool:
    return bool(_win().lock_region(fd))


def unlock(fd: int) -> None:
    _win().unlock_region(fd)


@contextmanager
def interprocess_lock(path: Path, timeout: float):
    win = _win()
    fd = open_private_file(path, write=True, create=True)
    try:
        deadline = time.monotonic() + max(0.0, float(timeout))
        while not try_lock_exclusive(fd):
            if time.monotonic() >= deadline:
                raise TimeoutError('Timed out waiting for lock')
            time.sleep(0.05)
        try:
            yield
        finally:
            unlock(fd)
    finally:
        win.close_fd(fd)


# ------------------------------------------------------------------- processes
def process_is_running_as_current_user(pid: int) -> bool:
    if type(pid) is not int or not 0 < pid <= 0xFFFFFFFF:
        return False
    try:
        win = _win()
        owner = win.open_process_owner_sid(pid)
        return owner is not None and owner == win.current_user_sid()
    except _SOFT:
        return False


def terminate_signals() -> list:
    return [getattr(signal, name) for name in ('SIGINT', 'SIGBREAK') if hasattr(signal, name)]


# ------------------------------------------------------------------- locations
def default_state_dir() -> Path:
    hermes_home = os.environ.get('HERMES_HOME')
    if hermes_home:
        return Path(hermes_home) / 'plugin-data' / 'hermes-custodian'
    local = os.environ.get('LOCALAPPDATA')
    base = Path(local) if local else Path.home() / 'AppData' / 'Local'
    return base / 'hermes-custodian'


# -------------------------------------------------------------------- scanning
def bounded_snapshot(root: Path, exclusions: list[str], max_files: int, max_file_bytes: int) -> dict:
    """Snapshot a scope without following reparse points.

    Only non-sensitive, singly-linked, non-reparse .py/.md files are opened and
    hashed; everything else is metadata-only and sensitive directories are never
    enumerated. Ancestors stay pinned without share-delete and all child opens
    resolve relative to their retained parent handles.
    """
    result = {'files': [], 'errors': [], 'complete': True}
    if (type(max_files) is not int or max_files <= 0
            or type(max_file_bytes) is not int or max_file_bytes <= 0
            or '..' in Path(root).parts
            or not isinstance(exclusions, list) or len(exclusions) > 100
            or any(not isinstance(p, str) or len(p) > 4096 for p in exclusions)):
        return {'files': [], 'errors': ['Invalid scan scope or limits'], 'complete': False}
    root = Path(os.path.abspath(root))
    deadline = time.monotonic() + MAX_SECONDS
    counters = {'visited': 0, 'bytes': 0}
    names = {}
    win = me = None
    pins = []

    def error(message):
        result['complete'] = False
        if len(result['errors']) < 100 and not (message == _ACL_ERROR and message in result['errors']):
            result['errors'].append(message)

    def check_time():
        if time.monotonic() >= deadline:
            raise _BudgetExceeded('Scan time budget exhausted')

    def resolve(sid):
        if sid not in names:
            names[sid] = principal_name(sid, win.lookup_sid if len(names) < MAX_NAME_LOOKUPS else None)
        return names[sid]

    def describe(path, info, handle):
        security = None
        if not info.is_reparse:     # GetNamedSecurityInfoW would follow a link
            try:
                security = win.get_dacl_entries(handle)
            except _SOFT:
                error(_ACL_ERROR)
        return build_metadata(path, info, security, (me,), resolve)

    def hash_file(parent, name, info):
        handle = win.open_child(parent, _component(name), 'read')
        try:
            opened = win.info(handle)
            if not opened.is_regular or opened.nlink != 1 or _signature(opened) != _signature(info):
                raise OSError('Entry replaced before read')
            digest = hashlib.sha256()
            remaining = info.size
            while remaining:
                check_time()
                chunk = win.read(handle, min(65536, remaining))
                if not chunk:
                    break
                counters['bytes'] += len(chunk)
                digest.update(chunk)
                remaining -= len(chunk)
            if remaining or _signature(win.info(handle)) != _signature(info):
                raise OSError('File changed during hashing')
            check_time()
            return digest.hexdigest()
        finally:
            win.close(handle)

    def walk(directory, handle, expected, depth=0):
        check_time()
        entries = win.list_names(handle, MAX_ENTRIES - counters['visited'] + 1)
        current = win.info(handle)
        if not current.is_dir or (current.dev, current.ino) != (expected.dev, expected.ino):
            raise OSError('Directory replaced before traversal')
        for name in entries:
            _component(name)
            check_time()
            if counters['visited'] >= MAX_ENTRIES:
                raise _BudgetExceeded('Traversal entry budget exhausted')
            counters['visited'] += 1
            if len(result['files']) >= max_files:
                error('File budget exhausted')
                return
            child = directory / name
            if is_excluded((str(child.relative_to(root)), str(child), name), exclusions):
                continue
            meta = win.open_child(handle, name, 'meta')
            try:
                info = win.info(meta)
                sensitive = _is_sensitive(child)
                if should_descend(info, sensitive):
                    if depth >= MAX_DEPTH:
                        raise _BudgetExceeded('Directory depth budget exhausted')
                    sub = win.open_child(handle, name, 'dir')
                    try:
                        current = win.info(sub)
                        if not current.is_dir or (current.dev, current.ino) != (info.dev, info.ino):
                            raise OSError('Directory replaced before traversal')
                        walk(child, sub, info, depth + 1)
                    finally:
                        win.close(sub)
                    continue
                item = describe(child, info, meta)
                if should_hash(info, sensitive, child.suffix):
                    if info.size > max_file_bytes:
                        error('File byte budget exceeded')
                        result['files'].append(item)
                        continue
                    if counters['bytes'] + info.size > MAX_TOTAL_BYTES:
                        raise _BudgetExceeded('Aggregate byte budget exhausted')
                    item['sha256'] = hash_file(handle, name, info)
                result['files'].append(item)
            finally:
                win.close(meta)

    try:
        check_time()
        win = _win()
        me = win.current_user_sid()
        handle = _pin_directory(win, root, pins)
        root_info = win.info(handle)
        if _is_sensitive(root):
            result['files'].append(describe(root, root_info, handle))
            return result
        # Listing requires FILE_LIST_DIRECTORY; pins need only attributes/control.
        listing = win.open_path(root.anchor, 'dir') if root == Path(root.anchor) else win.open_child(pins[-2], root.name, 'dir')
        try:
            current = win.info(listing)
            if not current.is_dir or (current.dev, current.ino) != (root_info.dev, root_info.ino):
                raise ValueError('Scan root replaced')
            walk(root, listing, root_info)
        finally:
            win.close(listing)
    except _BudgetExceeded as exc:
        error(str(exc))
    except _SOFT:
        error('Filesystem entry unavailable, changed, or unsafe')
    finally:
        for handle in reversed(pins):
            win.close(handle)
    return result


# Secure, bounded I/O over retained directory handles.
def _io_limit(value):
    if type(value) is not int or value < 0:
        raise ValueError('Invalid byte or entry limit')
    return value


def _io_path(path):
    path = Path(path)
    if '..' in path.parts:
        raise ValueError('Traversal is forbidden')
    return Path(os.path.abspath(path))


def _read_io_handle(win, handle, max_bytes, private=False):
    _io_limit(max_bytes)
    info = win.info(handle)
    if not info.is_regular or info.size > max_bytes:
        raise ValueError('File is nonregular or exceeds byte limit')
    if private:
        me = win.current_user_sid()
        security = win.get_dacl_entries(handle)
        if (info.nlink != 1 or security['owner'] not in (me, SID_ADMINISTRATORS)
                or classify_dacl(security['owner'], security['dacl'], (me,))['level'] != 'private'):
            raise ValueError('File must be private, current-user owned and singly linked')
    chunks, remaining = [], max_bytes + 1
    while remaining:
        chunk = win.read(handle, min(65536, remaining))
        if not chunk:
            break
        if len(chunk) > remaining:
            raise ValueError('Invalid read result')
        chunks.append(chunk)
        remaining -= len(chunk)
    if not remaining:
        raise ValueError('File exceeds byte limit')
    if _signature(info) != _signature(win.info(handle)):
        raise ValueError('File changed during read')
    return b''.join(chunks)


class _IODirectory:
    def __init__(self, win, handle):
        self.win, self.handle = win, handle

    def _active(self):
        if self.handle is None:
            raise ValueError('Directory capability is closed')
        return self.handle

    @contextmanager
    def open_directory(self, name):
        handle = self.win.open_child(self._active(), _component(name), 'dir')
        child = _IODirectory(self.win, handle)
        try:
            if not self.win.info(handle).is_dir:
                raise ValueError('Unsafe directory')
            yield child
        finally:
            child.handle = None
            self.win.close(handle)

    def read_file(self, name, *, max_bytes):
        _io_limit(max_bytes)
        handle = self.win.open_child(self._active(), _component(name), 'read')
        try:
            return _read_io_handle(self.win, handle, max_bytes)
        finally:
            self.win.close(handle)

    def directory_names(self, *, limit):
        _io_limit(limit)
        handle = self._active()
        result = []
        for name in self.win.list_names(handle, limit)[:limit]:
            child = self.win.open_child(handle, _component(name), 'meta')
            try:
                result.append(name if self.win.info(child).is_dir else None)
            finally:
                self.win.close(child)
        return result


@contextmanager
def open_directory_nofollow(path):
    win, pins = _win(), []
    directory = None
    try:
        path = _io_path(path)
        root = _pin_directory(win, path, pins)
        handle = (win.open_path(path.anchor, 'dir') if len(pins) == 1 else
                  win.open_child(pins[-2], _component(path.name), 'dir'))
        pins.append(handle)
        info, expected = win.info(handle), win.info(root)
        if not info.is_dir or (info.dev, info.ino) != (expected.dev, expected.ino):
            raise ValueError('Directory replaced')
        directory = _IODirectory(win, handle)
        yield directory
    finally:
        if directory is not None:
            directory.handle = None
        for handle in reversed(pins):
            win.close(handle)


def _read_io_path(path, max_bytes, private):
    _io_limit(max_bytes)
    path = _io_path(path)
    with open_directory_nofollow(path.parent) as directory:
        handle = directory.win.open_child(directory.handle, _component(path.name), 'read')
        try:
            return _read_io_handle(directory.win, handle, max_bytes, private)
        finally:
            directory.win.close(handle)


def read_private_file(path, *, max_bytes):
    return _read_io_path(path, max_bytes, True)


def read_file_nofollow(path, *, max_bytes):
    return _read_io_path(path, max_bytes, False)


def atomic_write_private_file(path, data):
    import secrets
    if not isinstance(data, bytes):
        raise TypeError('data must be bytes')
    path = _io_path(path)
    with open_directory_nofollow(path.parent) as directory:
        win, parent = directory.win, directory.handle
        handle = win.create_atomic(parent, '.custodian-' + secrets.token_hex(16))
        replaced = False
        try:
            _private_file(win, handle, win.current_user_sid(), created=True)
            view = memoryview(data)
            while view:
                chunk = bytes(view[:65536])
                count = win.write(handle, chunk)
                if not 0 < count <= len(chunk):
                    raise OSError('Short write')
                view = view[count:]
            win.flush(handle)
            win.replace(handle, parent, _component(path.name))
            replaced = True
        finally:
            try:
                if not replaced:
                    win.discard(handle)
            finally:
                win.close(handle)
