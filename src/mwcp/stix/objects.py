"""
This provides helper objects that can be used to generate STIX content
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from stix2 import v21 as stix

if TYPE_CHECKING:
    from mwcp.metadata import *


class STIXResult:
    """
    Provides a means to return STIX 2.1 content

    :var metadata: Bound metadata element towards this STIX content.
    :var linked_stix: An array of STIX objects that should be linked to a parent malware analysis object
    :var unlinked_stix: An array of STIX objects that should not be linked to a parent malware analysis object.
         This can include relationship objects, objects connected by relationship objects,
         and objects with embedded references like Notes
    :var note_content: The content of the note which will be attached to the STIX file object being analyzed by the
        malware analysis
    :var note_labels: The labels of the note which will be attached to the STIX file object being analyzed by the
        malware analysis
    """

    def __init__(self, metadata: Metadata, note_content: str = "", fixed_timestamp: str = None):
        self.metadata = metadata
        self.linked_stix = []
        self.unlinked_stix = []
        self.note_content = note_content
        self.note_labels = []
        self.fixed_timestamp = fixed_timestamp

    def add_linked(self, stix_content):
        self.linked_stix.append(stix_content)
        if note := self.create_tag_note(stix_content):
            self.add_unlinked(note)

    def add_unlinked(self, stix_content):
        self.unlinked_stix.append(stix_content)

    def create_tag_note(self, stix_content) -> Optional[stix.Note]:
        """
        Returns an object containing tag information for a given parent assuming there is content.
        """
        if tags := self.metadata.tags:
            return stix.Note(
                labels=tags,
                content=f"MWCP Tags: {', '.join(tags)}",
                object_refs=[stix_content.id],
                created=self.fixed_timestamp,
                modified=self.fixed_timestamp,
                allow_custom=True
            )

    def merge(self, other: STIXResult):
        self.linked_stix.extend(other.linked_stix)
        self.unlinked_stix.extend(other.unlinked_stix)

        if self.note_content == "":
            self.note_content = other.note_content
        elif other.note_content != "":
            self.note_content += "\n" + other.note_content

    def merge_ref(self, other: STIXResult):
        """
        A merge for when the target is a reference for the current object.
        """
        self.unlinked_stix.extend(other.linked_stix)
        self.unlinked_stix.extend(other.unlinked_stix)

        if self.note_content == "":
            self.note_content = other.note_content
        elif other.note_content != "":
            self.note_content += "\n" + other.note_content
