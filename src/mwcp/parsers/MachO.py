"""
Parses a Mach-O Universal Binary (FAT binary)
"""
from mwcp.exceptions import DependencyNotInstalled

try:
    import lief
except ImportError:
    raise DependencyNotInstalled("'lief' dependency not installed. Please install mwcp with 'parsers' extra.")

from mwcp import Parser, FileObject


class FATBinary(Parser):
    DESCRIPTION = "Mach-O FAT Binary"
    
    @classmethod
    def identify(cls, file_object):
        """
        Identify as a Mach-O FAT binary
        """
        # Avoid if already described as Mach-O
        if file_object.description and file_object.description.startswith("Mach-O"):
            return False
        return lief.is_macho(list(file_object.data))

    def parse_section(self, section: lief.MachO.Section, parent=None):
        """
        Parses embedded data in MachO section.
        """
        fo = FileObject(bytes(section.content), name=section.name, description="Mach-O Section")
        self.dispatcher.add(fo, parent=parent)

    def parse_segment(self, segment: lief.MachO.SegmentCommand, parent=None):
        """
        Parses a Mach-O segments.
        """
        segment_fo = FileObject(bytes(segment.content), name=segment.name, description="Mach-O Segment")
        self.dispatcher.add(segment_fo, parent=parent)
        for section in segment.sections:
            self.parse_section(section, parent=segment_fo)

    def parse_binary(self, binary: lief.MachO.Binary):
        """
        Parses embedded MachO.Binary in FAT Binary.
        """
        arch = binary.header.cpu_type.name
        data = binary.write_to_bytes()
        if data == self.file_object.data:
            # If binary is the same, avoid redispatching. Just redescribe.
            self.file_object.description = f"Mach-O Binary ({arch})"
            parent = self.file_object
        else:
            fo = FileObject(binary.write_to_bytes(), architecture=arch, description=f"Mach-O Binary ({arch})")
            self.dispatcher.add(fo)
            parent = fo
        for segment in binary.segments:
            self.parse_segment(segment, parent=parent)

    def run(self):
        """
        Parse the file with the FAT_HEADER construct
        """
        fat: lief.MachO.FatBinary = lief.MachO.parse(self.file_object.data)
        for binary in fat:
            self.parse_binary(binary)
