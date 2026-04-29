"""
Parses Python artifacts
"""

import os
from typing import Optional

import malstruct
from malstruct import this

from mwcp import FileObject, Parser
from mwcp.metadata import Version


class PyInstaller(Parser):
    DESCRIPTION = "PyInstaller"

    TABLE_ENTRY = malstruct.Struct(
        "entry_size" / malstruct.Int32ub,
        "offset" / malstruct.Int32ub,
        "compressed_size" / malstruct.Int32ub,
        "final_size" / malstruct.Int32ub,
        "flag" / malstruct.Flag,
        "type" / malstruct.String(1),
        "name" / malstruct.String(this.entry_size - 18),
        "data" / malstruct.Pointer(
            this.offset,
            malstruct.IfThenElse(
                this.flag,
                malstruct.Compressed(malstruct.Bytes(this.compressed_size), lib="zlib"),
                malstruct.Bytes(this.compressed_size),
            ),
        ),
    )

    @classmethod
    def identify(cls, file_object):
        """
        Validate the MAGIC data is at the appropriate location and return the correct spec to use
        for parsing.
        """
        magic = b'MEI\x0C\x0B\x0A\x0B\x0E'
        # pyinstaller 2.0
        if file_object.data[-24:-24 + len(magic)] == magic:
            cookie_spec = malstruct.Struct(
                "magic" / malstruct.Const(magic),
                "package_size" / malstruct.Int32ub,
                "toc_offset" / malstruct.Int32ub,
                "toc_entries" / malstruct.Int32ub,
                "python_version" / malstruct.Int32ub,
            )
            return True, cookie_spec

        # pyinstaller 2.1+
        elif file_object.data[-88:-88+len(magic)] == magic:
            cookie_spec = malstruct.Struct(
                "magic" / malstruct.Const(magic),
                "package_size" / malstruct.Int32ub,
                "toc_offset" / malstruct.Int32ub,
                "toc_entries" / malstruct.Int32ub,
                "python_version" / malstruct.Int32ub,
                "python_dll" / malstruct.String(64),
            )
            return True, cookie_spec

        return False

    def extract_entry(self, entry, hdr: bytes) -> Optional[FileObject]:
        """
        Extracts file data from table entry and returns it as a FileObject.
        """
        if not entry.data:
            return

        name = entry.name
        data = entry.data

        if entry.type in ('s', 'm', 'M'):  # python script/module/package
            if entry.type == 's' and entry.data[1:4] != b"\x00\x00\x00":  # uncompiled python code
                name += ".py"
            else:
                # it is a marshalled code object
                # we need to add the pyc header to the data so it can be decompiled
                name += ".pyc"
                data = hdr + data

        # TODO: Create a PYZ parser for extracting out individually compressed components.
        #   This will require determining a way to safely unmarshal data.
        #   (PyInstaller/loader/pyimod01_archive.py)
        # case 'z': # zlib archive (pyz)
        # case 'n': # symbolic link
        # case 'b': # binary
        # case 'Z': # zlib (pyz) - frozen Python code (zipfile)
        # case 'x': # data
        # case 'l': # splash resource

        return FileObject(data, file_name=name)

    def run(self, cookie_spec: malstruct.Struct):
        """
        Extract the cookie information in order to extract and parse the table of contents. Identify the .manifest
        filename in order to obtain the name of the target script to add to the dispatcher.
        """
        cookie_size = cookie_spec.sizeof()

        cookie = cookie_spec.parse(self.file_object.data[-cookie_size:])
        package = self.file_object.data[-cookie.package_size: -cookie_size]
        package_spec = malstruct.Struct(
            malstruct.Padding(cookie.toc_offset),
            "toc" / malstruct.GreedyRange(self.TABLE_ENTRY),
        )
        info = package_spec.parse(package)

        python_version = str(cookie.python_version)[0] + "." + str(cookie.python_version)[1:]
        self.report.add(Version(python_version).add_tag("Python"))

        # Extract files base on .manifest files.
        pyz = None
        target_names = []
        for entry in info.toc:
            if entry.name == "PYZ-00.pyz":
                pyz = entry
            elif entry.name.endswith(".manifest"):
                target_names.append(os.path.splitext(entry.name)[0].replace(".exe", ''))

        # Determine header for pyc files.
        if pyz:
            hdr = pyz.data[4:8] + b'\x00' * 12
        elif cookie.python_version >= 37:  # PEP 552 -- Deterministic pycs
            hdr = b"\x42\x0d\x0d\x0a" + b'\0' * 12  # Bitfield, Timestamp, size
        elif cookie.python_version >= 33:
            hdr = b"\x42\x0d\x0d\x0a" + b'\0' * 8  # (Timestamp + size)
        else:
            hdr = b"\x03\xF3\x0D\x0A" + b'\0' * 4  # Timestamp

        # If we had a .manifest, only extract those files.
        if target_names:
            for entry in info.toc:
                if entry.name in target_names or entry.data.startswith(b"PYZ\x00"):
                    if file := self.extract_entry(entry, hdr):
                        self.dispatcher.add(file)
        else:
            for entry in info.toc:
                if file := self.extract_entry(entry, hdr):
                    self.dispatcher.add(file)
