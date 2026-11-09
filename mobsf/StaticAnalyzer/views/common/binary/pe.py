#!/usr/bin/python
# coding=utf-8
"""
PE binary analysis for Windows executables and DLLs.

Checks security mitigations, dangerous imports, Rich header metadata,
TLS callbacks, and Authenticode signature status using LIEF.
"""
import logging
from pathlib import Path

import lief

from mobsf.StaticAnalyzer.views.common.binary.strings import (
    strings_on_binary,
)
from mobsf.MobSF.utils import run_with_timeout
from django.conf import settings

logger = logging.getLogger(__name__)

INFO = 'info'
WARNING = 'warning'
HIGH = 'high'

# Dangerous Win32 imports grouped by risk class
DANGEROUS_WIN32 = {
    'memory_manipulation': [
        'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx',
        'WriteProcessMemory', 'ReadProcessMemory', 'NtAllocateVirtualMemory',
        'NtWriteVirtualMemory',
    ],
    'remote_execution': [
        'CreateRemoteThread', 'CreateRemoteThreadEx', 'RtlCreateUserThread',
        'NtCreateThreadEx', 'QueueUserAPC',
    ],
    'code_injection': [
        'SetWindowsHookEx', 'SetWindowsHookExA', 'SetWindowsHookExW',
        'CreateProcess', 'CreateProcessA', 'CreateProcessW',
        'ShellExecute', 'ShellExecuteA', 'ShellExecuteW',
        'WinExec', 'system',
    ],
    'process_hollowing': [
        'NtUnmapViewOfSection', 'ZwUnmapViewOfSection',
        'SuspendThread', 'ResumeThread',
    ],
    'unsafe_string_ops': [
        'strcpy', 'strcat', 'sprintf', 'vsprintf', 'gets',
        'wcscpy', 'wcscat', 'swprintf',
    ],
    'anti_analysis': [
        'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
        'NtQueryInformationProcess', 'OutputDebugString',
        'GetTickCount', 'QueryPerformanceCounter',
    ],
    'network': [
        'WSAStartup', 'connect', 'send', 'recv',
        'InternetOpen', 'InternetConnect', 'HttpSendRequest',
        'URLDownloadToFile', 'URLDownloadToFileA', 'URLDownloadToFileW',
    ],
    'cryptography': [
        'CryptEncrypt', 'CryptDecrypt', 'CryptGenKey',
        'BCryptEncrypt', 'BCryptDecrypt', 'BCryptGenRandom',
    ],
    'registry': [
        'RegSetValueEx', 'RegCreateKeyEx', 'RegOpenKeyEx',
        'RegSetValueExA', 'RegSetValueExW',
    ],
}


class PEChecksec:
    def __init__(self, pe_file, rel_path=None):
        self.pe_path = str(pe_file)
        self.pe_rel = rel_path or Path(pe_file).name
        self.pe = run_with_timeout(
            lief.parse,
            settings.BINARY_ANALYSIS_TIMEOUT,
            self.pe_path)

    def checksec(self):
        pe_dict = {'name': self.pe_rel}
        if not self.is_pe():
            return {}
        pe_dict.update({
            'aslr': self._check_aslr(),
            'dep': self._check_dep(),
            'seh': self._check_seh(),
            'stack_guard': self._check_stack_guard(),
            'cfg': self._check_cfg(),
            'rfg': self._check_rfg(),
            'tls_callbacks': self._check_tls_callbacks(),
            'authenticode': self._check_authenticode(),
            'rich_header': self._get_rich_header(),
            'dangerous_imports': self._check_dangerous_imports(),
        })
        return pe_dict

    def is_pe(self):
        return self.pe is not None and isinstance(self.pe, lief.PE.Binary)

    def _check_aslr(self):
        """ASLR via IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE flag."""
        try:
            has_aslr = lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE in self.pe.optional_header.dll_characteristics_lists
            return {
                'has_aslr': has_aslr,
                'severity': INFO if has_aslr else HIGH,
                'description': (
                    'ASLR (Address Space Layout Randomization) is enabled via '
                    'DYNAMIC_BASE. The OS will rebase the image at load time, '
                    'making memory addresses unpredictable for attackers.'
                ) if has_aslr else (
                    'ASLR is disabled (DYNAMIC_BASE flag not set). Fixed load '
                    'addresses make ROP chains and return-to-libc attacks significantly '
                    'easier. Link with /DYNAMICBASE to enable ASLR.'
                ),
            }
        except Exception:
            return {'has_aslr': None, 'severity': INFO, 'description': 'ASLR check failed.'}

    def _check_dep(self):
        """DEP/NX via IMAGE_DLLCHARACTERISTICS_NX_COMPAT flag."""
        try:
            has_dep = lief.PE.DLL_CHARACTERISTICS.NX_COMPAT in self.pe.optional_header.dll_characteristics_lists
            return {
                'has_dep': has_dep,
                'severity': INFO if has_dep else HIGH,
                'description': (
                    'DEP/NX (Data Execution Prevention) is enabled. The binary '
                    'marks data pages as non-executable, preventing shellcode injection.'
                ) if has_dep else (
                    'DEP/NX is not enabled (NX_COMPAT flag absent). Data pages may '
                    'be executable, enabling shellcode injection. Link with /NXCOMPAT.'
                ),
            }
        except Exception:
            return {'has_dep': None, 'severity': INFO, 'description': 'DEP check failed.'}

    def _check_seh(self):
        """SafeSEH via IMAGE_DLLCHARACTERISTICS_NO_SEH and load config."""
        try:
            no_seh = lief.PE.DLL_CHARACTERISTICS.NO_SEH in self.pe.optional_header.dll_characteristics_lists
            if no_seh:
                return {
                    'seh': 'disabled',
                    'severity': INFO,
                    'description': 'SEH is disabled (NO_SEH set). The binary does not use structured exception handling.',
                }
            has_safe_seh = False
            try:
                lc = self.pe.load_configuration
                has_safe_seh = bool(lc and lc.se_handler_count > 0)
            except Exception:
                pass
            return {
                'seh': 'SafeSEH' if has_safe_seh else 'unsafe',
                'severity': INFO if has_safe_seh else WARNING,
                'description': (
                    f'SafeSEH is enabled with {self.pe.load_configuration.se_handler_count} '
                    'registered handlers. Only whitelisted handlers can be invoked.'
                ) if has_safe_seh else (
                    'SafeSEH is not enabled. Exception handler addresses are not validated, '
                    'allowing SEH-based exploits. Link with /SAFESEH.'
                ),
            }
        except Exception:
            return {'seh': 'unknown', 'severity': INFO, 'description': 'SEH check failed.'}

    def _check_stack_guard(self):
        """GS (stack security cookie) via load configuration."""
        try:
            lc = self.pe.load_configuration
            has_gs = bool(lc and lc.security_cookie != 0)
            return {
                'has_gs': has_gs,
                'severity': INFO if has_gs else HIGH,
                'description': (
                    'Stack security cookie (GS) is enabled. A canary value is '
                    'placed on the stack to detect and prevent buffer overflows '
                    'from overwriting the return address.'
                ) if has_gs else (
                    'Stack security cookie (GS) is not present in the load configuration. '
                    'The binary may be vulnerable to stack-based buffer overflow attacks. '
                    'Compile with /GS to enable stack protection.'
                ),
            }
        except Exception:
            return {'has_gs': None, 'severity': INFO, 'description': 'GS check failed.'}

    def _check_cfg(self):
        """Control Flow Guard via IMAGE_DLLCHARACTERISTICS_GUARD_CF and load config."""
        try:
            has_cfg = lief.PE.DLL_CHARACTERISTICS.GUARD_CF in self.pe.optional_header.dll_characteristics_lists
            return {
                'has_cfg': has_cfg,
                'severity': INFO if has_cfg else WARNING,
                'description': (
                    'Control Flow Guard (CFG) is enabled. Windows validates indirect '
                    'call targets against a bitmap of valid function addresses, '
                    'preventing most ROP/JOP attacks at the OS level.'
                ) if has_cfg else (
                    'Control Flow Guard (CFG) is not enabled. Indirect calls are not '
                    'validated by the OS. Link with /GUARD:CF to enable CFG.'
                ),
            }
        except Exception:
            return {'has_cfg': None, 'severity': INFO, 'description': 'CFG check failed.'}

    def _check_rfg(self):
        """Return Flow Guard (Shadow Stack / CET) via load configuration guard flags."""
        try:
            lc = self.pe.load_configuration
            has_rfg = False
            try:
                # GUARD_RF_INSTRUMENTED = 0x00020000
                # GUARD_XFG_ENABLED     = 0x00800000
                flags = getattr(lc, 'guard_flags', 0)
                has_rfg = bool(flags & 0x00020000)
            except Exception:
                pass
            return {
                'has_rfg': has_rfg,
                'severity': INFO,
                'description': (
                    'Return Flow Guard (RFG/Shadow Stack CET) is enabled. '
                    'Return addresses are validated against a shadow copy, '
                    'preventing return-oriented programming attacks.'
                ) if has_rfg else (
                    'Return Flow Guard (RFG) is not enabled. This is an optional '
                    'hardening feature; consider enabling with /CETCOMPAT on '
                    'Windows 10 20H1+ for stronger ROP mitigation.'
                ),
            }
        except Exception:
            return {'has_rfg': None, 'severity': INFO, 'description': 'RFG check failed.'}

    def _check_tls_callbacks(self):
        """TLS callbacks can execute before main() — often used by packers/anti-debug."""
        try:
            callbacks = []
            if self.pe.has_tls:
                tls = self.pe.tls
                callbacks = [hex(c) for c in (tls.callbacks or [])]
            if callbacks:
                return {
                    'has_tls_callbacks': True,
                    'callbacks': callbacks,
                    'severity': WARNING,
                    'description': (
                        f'The binary has {len(callbacks)} TLS callback(s) at: '
                        f'{", ".join(callbacks)}. TLS callbacks execute before main() '
                        'and are frequently used by malware, packers, and anti-debug '
                        'techniques to run code before the debugger attaches.'
                    ),
                }
            return {
                'has_tls_callbacks': False,
                'callbacks': [],
                'severity': INFO,
                'description': 'No TLS callbacks found.',
            }
        except Exception:
            return {'has_tls_callbacks': None, 'callbacks': [], 'severity': INFO, 'description': 'TLS check failed.'}

    def _check_authenticode(self):
        """Authenticode digital signature status."""
        try:
            if not self.pe.has_signature:
                return {
                    'is_signed': False,
                    'severity': WARNING,
                    'description': (
                        'The binary is not Authenticode-signed. Unsigned executables '
                        'trigger Windows SmartScreen warnings and cannot be verified '
                        'for integrity or publisher identity.'
                    ),
                }
            sig = self.pe.signatures[0]
            signer = ''
            try:
                cert = sig.signers[0].cert
                signer = cert.subject
            except Exception:
                pass
            return {
                'is_signed': True,
                'signer': signer,
                'severity': INFO,
                'description': f'Binary is Authenticode-signed. Signer: {signer or "unknown"}.',
            }
        except Exception:
            return {'is_signed': None, 'severity': INFO, 'description': 'Authenticode check failed.'}

    def _get_rich_header(self):
        """Rich header: compiler/linker fingerprint embedded by MSVC toolchain."""
        try:
            if not self.pe.has_rich_header:
                return {
                    'has_rich_header': False,
                    'entries': [],
                    'severity': INFO,
                    'description': 'No Rich header found (binary may be packed, rebuilt, or non-MSVC).',
                }
            entries = []
            for e in self.pe.rich_header.entries:
                entries.append({
                    'id': e.id,
                    'build_id': e.build_id,
                    'count': e.count,
                })
            return {
                'has_rich_header': True,
                'entries': entries[:20],
                'severity': INFO,
                'description': (
                    f'Rich header present with {len(self.pe.rich_header.entries)} entries. '
                    'The Rich header encodes the MSVC compiler version and object file '
                    'counts used to build this binary — useful for attribution and '
                    'compiler fingerprinting.'
                ),
            }
        except Exception:
            return {'has_rich_header': None, 'entries': [], 'severity': INFO, 'description': 'Rich header check failed.'}

    def _check_dangerous_imports(self):
        """Flag dangerous Win32 API imports grouped by risk class."""
        try:
            imported = set()
            for imp in self.pe.imports:
                for entry in imp.entries:
                    if entry.name:
                        imported.add(entry.name)
            found = {}
            for risk_class, funcs in DANGEROUS_WIN32.items():
                matched = [f for f in funcs if f in imported]
                if matched:
                    found[risk_class] = matched
            if found:
                all_funcs = [f for funcs in found.values() for f in funcs]
                severity = HIGH if any(
                    k in found for k in (
                        'memory_manipulation', 'remote_execution',
                        'code_injection', 'process_hollowing')
                ) else WARNING
                return {
                    'has_dangerous_imports': True,
                    'by_class': found,
                    'total': len(all_funcs),
                    'severity': severity,
                    'description': (
                        f'Found {len(all_funcs)} potentially dangerous Win32 API import(s) '
                        f'across {len(found)} risk class(es): {", ".join(found.keys())}. '
                        'These APIs are commonly abused for code injection, process hollowing, '
                        'anti-analysis, and malware persistence.'
                    ),
                }
            return {
                'has_dangerous_imports': False,
                'by_class': {},
                'total': 0,
                'severity': INFO,
                'description': 'No high-risk Win32 API imports detected.',
            }
        except Exception:
            return {
                'has_dangerous_imports': None,
                'by_class': {},
                'total': 0,
                'severity': INFO,
                'description': 'Import check failed.',
            }

    def get_symbols(self):
        symbols = []
        try:
            for sym in self.pe.symbols:
                if sym.name:
                    symbols.append(sym.name)
        except Exception:
            pass
        return symbols

    def strings(self):
        return strings_on_binary(self.pe_path)
