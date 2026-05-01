"""
Parses emulated components from a generic executable.
"""
import re
from typing import Union, Tuple, Any

from mwcp.exceptions import DependencyNotInstalled

try:
    import rugosa
except ImportError:
    raise DependencyNotInstalled(f"'rugosa' dependency not installed. Please install mwcp with 'parsers' extra.")
from rugosa import MaxExecutionHit, EmulationError
from rugosa.emulation.objects import *
from rugosa.emulation.actions import *
from rugosa.emulation.emulator import IterContextArgs
from rugosa.emulation.monitors import ObjectMonitor, StackStringsMonitor, ActionMonitor

from mwcp import metadata, Parser, FileObject



class Generic(Parser):
    """
    Performs generic emulation of the sample in order to extract notable objects.

    Reads in the following config from parser_config.yml:
        disassembler: ida  # backend disassembler to use. (works best with IDA)
        depth: 0  # number of calls up the stack
        call_depth: 1   # number of function calls we are allowed to emulate into
        exhaustive: false  # whether to process all code paths
        follow_loops: false  # whether to emulate loops
        max_instructions: 100_000  # max number of instructions to emulate per code path.
        min_length: 5  # Minimum number of characters to count as a string.
    """
    DESCRIPTION = "Generic Executable"

    emulation_config = IterContextArgs(
        depth=0,
        call_depth=1,
        exhaustive=False,
        follow_loops=False
    )

    # Used to ignore the default filename created by the rugosa emulator.
    _default_filename = re.compile(r"0x[a-fA-F0-9]+\.bin")

    def report_file(self, file: File):
        if file.data:
            name = file.name
            if name and self._default_filename.match(name):
                name = None
            self.dispatcher.add(FileObject(file.data, name=name))
        if (path := file.path) and not self._default_filename.match(path):
            self.report.add(metadata.FilePath(path))
        for path in file.history:
            if not self._default_filename.match(path):
                self.report.add(metadata.FilePath(path))

    def report_regkey(self, regkey: RegKey):
        values = regkey.values
        if values:
            # If we have data set in the registry, add an element for each instance.
            for value in values:
                if isinstance(value, tuple):
                    value = list(value)
                self.report.add(metadata.Registry2(
                    subkey=regkey.root_key,
                    value=regkey.sub_key,
                    data=value,
                ))
        else:
            self.report.add(metadata.Registry2(
                subkey=regkey.root_key,
                value=regkey.sub_key
            ))

    def report_service(self, service: Service):
        self.report.add(metadata.Service(
            name=service.name,
            display_name=service.display_name,
            description=service.description,
            image=service.binary_path,

        ))

    def run(self):
        emulation_config = self.emulation_config.copy()
        # Pull from parser configuration if available.
        emulation_config.update(
            {key: value for key, value in self.config.items() if key in IterContextArgs.__annotations__}
        )
        disassembler = self.config.get("disassembler")

        with self.file_object.disassembly(disassembler) as dis:
            emulator = rugosa.Emulator(
                dis,
                branch_tracking=False,
                max_instructions=self.config.get("max_instructions", 100_000),
            )

            # Create monitors
            objects = ObjectMonitor(scope="block")
            actions = ActionMonitor(scope="code_path")
            stack_strings = StackStringsMonitor(min_length=self.config.get("min_length", 5))

            emulator.add_monitor(objects)
            emulator.add_monitor(actions)
            emulator.add_monitor(stack_strings)

            for func in dis.functions():
                if func.is_library:
                    continue

                try:
                    emulator.exhaust(func.start, **emulation_config)
                except (MaxExecutionHit, EmulationError, TimeoutError) as e:
                    self.logger.warning(f"Did not complete emulation at {func.name} (0x{func.start:08x}): {e}")

                # Report objects.
                for object in objects.latest():
                    if isinstance(object, File):
                        self.report_file(object)
                    elif isinstance(object, RegKey):
                        self.report_regkey(object)
                    elif isinstance(object, Service):
                        self.report_service(object)

                # Report actions.
                for action in actions.latest():
                    if isinstance(action, CommandExecuted):
                        self.report.add(metadata.Command(action.command))
                    elif isinstance(action, DirectoryCreated):
                        self.report.add(metadata.Directory(action.path))
                    elif isinstance(action, ShellOperation):
                        if action.operation:
                            command = action.operation
                            if action.parameters:
                                command += " " + action.parameters
                            self.report.add(metadata.Command(command))
                        if action.directory:
                            self.report.add(metadata.Directory(action.directory))

                # Report stack strings.
                for string in stack_strings:
                    self.report.add(metadata.DecodedString(str(string)))
                stack_strings.clear()


class PE(Generic):
    DESCRIPTION = "PE Executable"

    @classmethod
    def identify(cls, file_object):
        return bool(file_object.pe)


class ELF(Generic):
    DESCRIPTION = "ELF Executable"

    @classmethod
    def identify(cls, file_object):
        return bool(file_object.elf)
