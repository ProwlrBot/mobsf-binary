#!/usr/bin/python
# coding=utf-8
"""
JNI bridge analyzer: cross-references Java native method declarations
against ELF exports to surface unimplemented or orphaned JNI functions.

Finds:
  - Native methods declared in Java/Kotlin that have no matching ELF export
  - ELF-exported JNI_OnLoad and RegisterNatives patterns
  - JNI functions exported from .so files that have no Java declaration
"""
import logging
import re
from pathlib import Path

import lief

logger = logging.getLogger(__name__)

# JNI name-mangling: Java_<pkg>_<class>_<method>
# e.g. Java_com_example_NativeLib_stringFromJNI
_JNI_EXPORT_RE = re.compile(r'^Java_[A-Za-z0-9_$]+$')


def _mangle_jni(class_fqn: str, method: str) -> str:
    """Convert fully-qualified class + method to JNI symbol name."""
    mangled = class_fqn.replace('.', '_').replace('/', '_').replace('$', '_00024')
    return f'Java_{mangled}_{method}'


def _get_elf_exports(so_path: str) -> set:
    """Return the set of exported symbol names from an ELF binary."""
    exports = set()
    try:
        binary = lief.parse(so_path)
        if not binary:
            return exports
        for sym in binary.exported_symbols:
            if sym.name:
                exports.add(sym.name)
    except Exception as e:
        logger.warning('JNI bridge: failed to parse %s — %s', so_path, e)
    return exports


def _has_register_natives(exports: set) -> bool:
    """Check if the binary uses RegisterNatives (dynamic JNI registration)."""
    return 'JNI_OnLoad' in exports


def analyze_jni_bridge(java_native_methods: list, so_files: list) -> dict:
    """
    Cross-reference Java native method declarations against .so exports.

    Args:
        java_native_methods: list of dicts with keys:
            - class_name: str  (e.g. "com.example.NativeLib")
            - method_name: str (e.g. "stringFromJNI")
            - signature: str   (e.g. "()Ljava/lang/String;")
            - file: str        (source file path, for reference)
        so_files: list of absolute paths (str or Path) to .so binaries

    Returns:
        dict with:
            - unimplemented: Java native methods with no matching ELF export
            - dynamic_registration: .so files using RegisterNatives / JNI_OnLoad
            - orphaned_exports: JNI exports with no Java declaration found
            - summary: human-readable summary string
    """
    result = {
        'unimplemented': [],
        'dynamic_registration': [],
        'orphaned_exports': [],
        'summary': '',
    }
    if not java_native_methods and not so_files:
        result['summary'] = 'No native methods or shared libraries to analyze.'
        return result

    # Collect all JNI exports across all .so files
    all_exports = set()
    so_export_map = {}
    for so_path in so_files:
        exports = _get_elf_exports(str(so_path))
        so_export_map[str(so_path)] = exports
        all_exports.update(exports)
        if _has_register_natives(exports):
            result['dynamic_registration'].append({
                'library': Path(so_path).name,
                'note': (
                    'Exports JNI_OnLoad — likely uses RegisterNatives() for dynamic '
                    'method registration. Static JNI symbol matching may undercount '
                    'the actual native surface.'
                ),
            })

    # Find Java native methods with no matching ELF export
    declared_jni_symbols = set()
    for method in java_native_methods:
        cls = method.get('class_name', '')
        mth = method.get('method_name', '')
        expected_sym = _mangle_jni(cls, mth)
        declared_jni_symbols.add(expected_sym)
        if expected_sym not in all_exports:
            result['unimplemented'].append({
                'class': cls,
                'method': mth,
                'expected_symbol': expected_sym,
                'source_file': method.get('file', ''),
                'note': (
                    'No matching ELF export found. The method may use RegisterNatives '
                    'for dynamic registration, or the native implementation is missing.'
                ),
            })

    # Find JNI exports from .so with no Java declaration
    for sym in all_exports:
        if _JNI_EXPORT_RE.match(sym) and sym not in declared_jni_symbols:
            result['orphaned_exports'].append({
                'symbol': sym,
                'note': (
                    'JNI-mangled export with no corresponding Java native declaration. '
                    'May indicate dead code, a hidden entry point, or a class '
                    'not discovered during static analysis.'
                ),
            })

    u = len(result['unimplemented'])
    d = len(result['dynamic_registration'])
    o = len(result['orphaned_exports'])
    total_declared = len(java_native_methods)
    result['summary'] = (
        f'Analyzed {total_declared} declared native method(s) across {len(so_files)} '
        f'shared librar{"ies" if len(so_files) != 1 else "y"}. '
        f'Unimplemented: {u}, dynamic registration detected: {d}, '
        f'orphaned JNI exports: {o}.'
    )
    return result
