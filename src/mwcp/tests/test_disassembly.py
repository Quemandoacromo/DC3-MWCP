"""
Tests components that use Dragodis disassembly.
"""

import os

import pytest

import mwcp
from mwcp import metadata
from mwcp.tests.test_parsers import _test_parser

dragodis = pytest.importorskip("dragodis", reason="Dragodis not installed")


@pytest.mark.parametrize("backend", ["ida", "ghidra", "vivisect"])
def test_disassembly(datadir, backend):
    """Tests basic disassembly"""
    strings_exe = datadir / "strings.exe"

    input_file = mwcp.FileObject.from_path(strings_exe)
    try:
        with input_file.disassembly(backend) as dis:
            insn = dis.get_instruction(0x401000)
            assert insn.mnemonic == "push"
    except dragodis.NotInstalledError as e:
        pytest.skip(e)


@pytest.mark.parametrize("backend", ["ida", "ghidra", "vivisect"])
def test_file_object_disassembly(datadir, backend):
    """Tests disassembler project file gets reported when using FileObject.disassembly()"""
    strings_exe = datadir / "strings.exe"

    input_file = mwcp.FileObject.from_path(strings_exe)
    report = mwcp.Report(input_file, "FooParser")
    with report:
        try:
            with input_file.disassembly(backend, report=report) as dis:
                line = dis.get_line(0x401000)
                line.set_comment("test comment")
        except dragodis.NotInstalledError as e:
            pytest.skip(e)
    # After we leave disassembly context, we should see the project file in the report.
    files = report.get(metadata.File)
    assert len(files) == 1
    project_file = files[0]
    assert project_file.data
    if backend == "ida":
        assert project_file.name in ("strings.exe.idb", "strings.exe.i64")
    elif backend == "ghidra":
        assert project_file.name == "strings.exe_ghidra.zip"
    else:
        assert project_file.name == "strings.exe.viv"
    assert project_file.derivation == "supplemental"


def test_file_object_stack_strings(datadir):
    """
    Tests .stack_strings property.
    """
    strings_exe = datadir / "strings.exe"
    input_file = mwcp.FileObject.from_path(strings_exe)
    # TODO: This is a bad sample to test this. There are no real stack strings generated.
    assert input_file.stack_strings(min_length=2) == ["0X"]


def test_file_object_static_strings(datadir):
    """
    Tests .static_strings property.
    """
    strings_exe = datadir / "strings.exe"
    input_file = mwcp.FileObject.from_path(strings_exe)
    assert input_file.static_strings() == [
        '(null)', 'Idmmn!Vnsme ', 'Vgqv"qvpkle"ukvj"ig{"2z20', 'Wkf#rvj`h#aqltm#el{#ivnsp#lufq#wkf#obyz#gld-',
        'Keo$mw$wpvkjc$ej`$ehwk$cmraw$wle`a*', 'Dfla%gpwkv%mji`v%lk%rjji%fijqm+', 'Egru&ghb&biau&cgen&ngrc&rnc&irnct(',
        '+()./,-"#*', '`QFBWFsQL@FPPb', 'tSUdFS', '@AKJDGBA@KJGDBJKAGDC',
        'LMFOGHKNLMGFOHKFGNLKHNMLOKGNKGHFGLHKGLMHKGOFNMLHKGFNLMJNMLIJFGNMLOJIMLNGFJHNM', 'DecodePointer',
        'EncodePointer', 'USER32.DLL', 'MessageBoxA', 'GetActiveWindow', 'GetLastActivePopup',
        'GetUserObjectInformationA', 'GetProcessWindowStation', 'Runtime Error!\n\nProgram: ',
        '<program name unknown>', 'Microsoft Visual C++ Runtime Library', 'CorExitProcess', 'FlsAlloc', 'FlsGetValue',
        'FlsSetValue', 'FlsFree', 'CONOUT$', '(null)', 'KERNEL32.DLL', 'mscoree.dll'
    ]


@pytest.mark.parametrize("backend", ["ida", "ghidra", "vivisect"])
def test_Sample(pytestconfig, datadir, backend):
    """Tests running the Sample parser."""
    mwcp.register_parser_directory(str(datadir), source_name="test")
    os.environ["DRAGODIS_DISASSEMBLER"] = backend
    input_file_path = datadir / "strings.exe"
    results_path = datadir / "strings.json"

    try:
        _test_parser(pytestconfig, input_file_path, results_path)
    except dragodis.NotInstalledError as e:
        pytest.skip(e)
