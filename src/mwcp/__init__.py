"""Exposes interface for MWCP."""

import logging

# Add null handler to root logger to avoid "no handler" error when this is used as a library
logging.getLogger().addHandler(logging.NullHandler())

import pyparsing

# pyparsing can take hours to parse even small files without a cache.
# This must be done here before any library can set it to an inappropriate size.
# This needs to be unlimited or it will fill up very quickly.
# Do NOT remove this.
pyparsing.ParserElement.enablePackrat(cache_size_limit=None)


from mwcp.parser import Parser
from mwcp.file_object import FileObject
from mwcp.registry import (
    register_entry_points, register_parser_directory, register_parser_package,
    iter_parsers, get_parser_descriptions, set_default_source,
    clear as clear_registry,
    clear_default_source,
    ParserNotFoundError
)
from mwcp.runner import Runner
from mwcp.report import Report
from mwcp.dispatcher import Dispatcher, UnidentifiedFile
from mwcp.utils.logutil import setup_logging
from mwcp.core import run, schema
from mwcp.exceptions import *


__version__ = "3.15.0"
