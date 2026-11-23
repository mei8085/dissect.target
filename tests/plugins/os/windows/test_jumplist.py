from __future__ import annotations

import io
import struct
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.plugins.os.windows import jumplist as jumplist_module
from dissect.target.plugins.os.windows.jumplist import (
    AutomaticDestinationFile,
    CustomDestinationFile,
    JumpListEntry,
    JumpListPlugin,
)
from dissect.target.plugins.os.windows.lnk import LnkRecord
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


CUSTOM_DESTINATION_FILENAME = "590aee7bdd69b59b.customDestinations-ms"
AUTOMATIC_DESTINATION_FILENAME = "5f7b5f1e01b83767.automaticDestinations-ms"
CUSTOM_DESTINATION_FOOTER = b"\xab\xfb\xbf\xba"
MINI_SECTOR_SIZE = 64
SECTOR_SIZE = 512
FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
NOSTREAM = 0xFFFFFFFF


# ---------------------------------------------------------------------------
# In-memory fixture builders (no binary test data required)
# ---------------------------------------------------------------------------


def minimal_lnk() -> bytes:
    """Return a minimal, self-contained LNK file that the LNK parser accepts."""
    link_clsid = bytes.fromhex("0114020000000000c000000000000046")
    header = struct.pack("<I", 0x4C)  # header size
    header += link_clsid
    header += struct.pack("<I", 0)  # link flags
    header += struct.pack("<I", 0x20)  # file attributes (archive)
    header += b"\x00" * 24  # creation/access/write times
    header += struct.pack("<I", 0)  # file size
    header += struct.pack("<i", 0)  # icon index
    header += struct.pack("<I", 1)  # show command
    header += struct.pack("<H", 0)  # hot key
    header += b"\x00" * 10  # reserved
    header += struct.pack("<I", 0)  # terminal extra-data block
    return header


class _DirectoryEntry:
    def __init__(self, name: str, entry_type: int):
        name_utf16 = name.encode("utf-16-le") + b"\x00\x00"
        self.name_field = name_utf16 + b"\x00" * (-len(name_utf16) % 64)
        self.name_len = len(name_utf16)
        self.entry_type = entry_type  # 1 = storage, 2 = stream, 5 = root
        self.color = 1
        self.left_sib = NOSTREAM
        self.right_sib = NOSTREAM
        self.child_sib = NOSTREAM
        self.starting_sector = FREESECT
        self.stream_size = 0
        self.children: list[_DirectoryEntry] = []

    def bytes(self) -> bytes:
        out = self.name_field
        out += struct.pack("<H", self.name_len)
        out += struct.pack("<BB", self.entry_type, self.color)
        out += struct.pack("<III", self.left_sib, self.right_sib, self.child_sib)
        out += b"\x00" * 16  # CLSID
        out += struct.pack("<I", 0)  # state bits
        out += struct.pack("<QQ", 0, 0)  # creation / modification time
        out += struct.pack("<I", self.starting_sector)
        out += struct.pack("<Q", self.stream_size)
        assert len(out) == 128
        return out


def build_ole_file(storages: dict[str, bytes]) -> bytes:
    """Build a minimal version-3 OLE compound file with named storages.

    Each ``storages`` key becomes a root-level storage holding a single stream
    named ``<key>.lnk`` with the provided payload.
    """
    root = _DirectoryEntry("Root Entry", 5)
    entries = [root]
    storage_entries = []
    stream_entries = []

    for storage_name, payload in storages.items():
        storage = _DirectoryEntry(storage_name, 1)
        stream = _DirectoryEntry(f"{storage_name}.lnk", 2)
        stream.stream_size = len(payload)
        storage.children.append(stream)
        storage_entries.append(storage)
        stream_entries.append((stream, payload))
        entries.extend((storage, stream))

    # Mini stream: every payload occupies one or more 64-byte mini sectors.
    mini_sector_data = []
    mini_chain = []
    cursor = 0
    for stream, payload in stream_entries:
        count = max(1, (len(payload) + MINI_SECTOR_SIZE - 1) // MINI_SECTOR_SIZE)
        indices = list(range(cursor, cursor + count))
        cursor += count
        mini_chain.append((stream, indices))
        mini_sector_data.append(payload + b"\x00" * (count * MINI_SECTOR_SIZE - len(payload)))
        stream.starting_sector = indices[0]
    mini_stream = b"".join(mini_sector_data)

    # Mini FAT chains.
    minifat = []
    for _stream, indices in mini_chain:
        for i, _index in enumerate(indices):
            minifat.append(ENDOFCHAIN if i == len(indices) - 1 else indices[i + 1])
    minifat_bytes = b"".join(struct.pack("<I", entry) for entry in minifat)
    minifat_count = max(1, (len(minifat_bytes) + SECTOR_SIZE - 1) // SECTOR_SIZE)
    minifat_bytes += b"\x00" * (minifat_count * SECTOR_SIZE - len(minifat_bytes))

    # The mini stream itself is stored in regular sectors, owned by the root entry.
    mini_sector_count = max(1, (len(mini_stream) + SECTOR_SIZE - 1) // SECTOR_SIZE)
    mini_stream += b"\x00" * (mini_sector_count * SECTOR_SIZE - len(mini_stream))

    # Directory tree: root -> storages -> streams, linked through right siblings.
    def link(nodes: list[_DirectoryEntry]) -> None:
        for i, node in enumerate(nodes):
            node.left_sib = NOSTREAM
            node.right_sib = entries.index(nodes[i + 1]) if i + 1 < len(nodes) else NOSTREAM

    link(storage_entries)
    if storage_entries:
        root.child_sib = entries.index(storage_entries[0])
    for storage in storage_entries:
        link(storage.children)
        storage.child_sib = entries.index(storage.children[0])

    directory_bytes = b"".join(entry.bytes() for entry in entries)
    directory_count = max(1, (len(directory_bytes) + SECTOR_SIZE - 1) // SECTOR_SIZE)
    directory_bytes += b"\x00" * (directory_count * SECTOR_SIZE - len(directory_bytes))

    mini_start = 0
    minifat_start = mini_sector_count
    directory_start = minifat_start + minifat_count
    data_sector_count = mini_sector_count + minifat_count + directory_count

    fat_count = 1
    while (data_sector_count + fat_count + 127) // 128 > fat_count:
        fat_count += 1
    fat_start = directory_start + directory_count

    fat = [FREESECT] * (fat_count * 128)

    def mark_chain(start: int, count: int) -> None:
        for offset in range(count):
            fat[start + offset] = ENDOFCHAIN if offset == count - 1 else start + offset + 1

    mark_chain(mini_start, mini_sector_count)
    mark_chain(minifat_start, minifat_count)
    mark_chain(directory_start, directory_count)
    for i in range(fat_count):
        fat[fat_start + i] = FATSECT

    root.starting_sector = mini_start
    root.stream_size = len(mini_stream)
    directory_bytes = b"".join(entry.bytes() for entry in entries)
    directory_bytes += b"\x00" * (directory_count * SECTOR_SIZE - len(directory_bytes))

    difat = [FREESECT] * 109
    for i in range(fat_count):
        difat[i] = fat_start + i

    header = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    header += b"\x00" * 16  # CLSID
    header += struct.pack("<HHHHH", 0x003E, 0x0003, 0xFFFE, 9, 6)
    header += b"\x00" * 6  # reserved
    header += struct.pack("<I", 0)  # directory sector count (always 0 in version 3)
    header += struct.pack("<I", fat_count)
    header += struct.pack("<I", directory_start)
    header += struct.pack("<I", 0)  # transaction signature
    header += struct.pack("<I", 4096)  # mini stream cutoff
    header += struct.pack("<II", minifat_start, minifat_count)
    header += struct.pack("<II", ENDOFCHAIN, 0)  # DIFAT
    header += b"".join(struct.pack("<I", entry) for entry in difat)
    assert len(header) == SECTOR_SIZE

    fat_bytes = b"".join(struct.pack("<I", entry) for entry in fat)
    return header + mini_stream + minifat_bytes + directory_bytes + fat_bytes


def build_custom_destination(body: bytes, number_of_entries: int = 0) -> bytes:
    """Wrap ``body`` in a valid version 2 CustomDestination envelope (value_type 1)."""
    header = struct.pack("<iiii", 2, 0, 0, 1)
    header_end = struct.pack("<i", number_of_entries)
    return header + header_end + body + CUSTOM_DESTINATION_FOOTER


def _empty_lnk_record(target: Target, destination: object) -> LnkRecord:
    return LnkRecord(
        lnk_path=destination,
        lnk_name=None,
        lnk_mtime=None,
        lnk_atime=None,
        lnk_ctime=None,
        lnk_relativepath=None,
        lnk_workdir=None,
        lnk_arguments=None,
        lnk_iconlocation=None,
        local_base_path=None,
        common_path_suffix=None,
        lnk_full_path=None,
        lnk_net_name=None,
        lnk_device_name=None,
        machine_id=None,
        target_mtime=None,
        target_atime=None,
        target_ctime=None,
        _target=target,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_os_windows_jumplist(target_win_users: Target, fs_win: VirtualFilesystem) -> None:
    custom_destination = absolute_path("_data/plugins/os/windows/jumplist/590aee7bdd69b59b.customDestinations-ms")
    automatic_destination = absolute_path("_data/plugins/os/windows/jumplist/5f7b5f1e01b83767.automaticDestinations-ms")

    user_details = target_win_users.user_details.find(username="John")

    fs_win.map_file(
        str(
            user_details.home_path.joinpath(
                "AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/590aee7bdd69b59b.customDestinations-ms"
            )
        )[3:],  # drop C:/
        custom_destination,
    )
    fs_win.map_file(
        str(
            user_details.home_path.joinpath(
                "AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/5f7b5f1e01b83767.automaticDestinations-ms"
            )
        )[3:],  # drop C:/
        automatic_destination,
    )

    target_win_users.add_plugin(JumpListPlugin)

    records = list(target_win_users.jumplist())
    assert len(records) == 3

    custom_records = [record for record in records if record.type == "customDestinations"]
    automatic_records = [record for record in records if record.type == "automaticDestinations"]
    assert len(custom_records) >= 1
    assert len(automatic_records) >= 1

    record = custom_records[0]
    assert record.application_id == "590aee7bdd69b59b"
    assert record.application_name == "Powershell Windows 10"
    # Every record must retain a traceable, in-container source location.
    assert all(record.source for record in records)
    # Automatic and custom destinations keep their own evidence identity,
    # even when they point at the same target path.
    assert {record.type for record in records} == {"customDestinations", "automaticDestinations"}
    # Custom destinations locate entries by absolute byte offset, automatic
    # destinations locate them by their OLE storage name.
    assert all(record.source.startswith("0x") for record in custom_records)
    assert all(record.source for record in automatic_records)


def test_os_windows_jumplist_automatic_destination_sources() -> None:
    ole_file = build_ole_file({"1": minimal_lnk(), "2": minimal_lnk()})

    jumplist = AutomaticDestinationFile(io.BytesIO(ole_file), AUTOMATIC_DESTINATION_FILENAME)
    entries = list(jumplist)

    assert jumplist.type == "automaticDestinations"
    assert jumplist.id == "5f7b5f1e01b83767"
    assert [entry.source for entry in entries] == ["1.lnk", "2.lnk"]
    assert all(isinstance(entry, JumpListEntry) for entry in entries)
    assert all(entry.lnk.link_header is not None for entry in entries)


def test_os_windows_jumplist_automatic_destination_skips_broken_entry() -> None:
    ole_file = build_ole_file({"1": minimal_lnk(), "2": b"\x00" * 8, "3": minimal_lnk()})

    jumplist = AutomaticDestinationFile(io.BytesIO(ole_file), AUTOMATIC_DESTINATION_FILENAME)
    entries = list(jumplist)

    # The container still yields every entry; the incomplete one keeps its own source
    # but simply lacks a parsed link header instead of erasing the other entries.
    assert [entry.source for entry in entries] == ["1.lnk", "2.lnk", "3.lnk"]
    assert [entry.lnk.link_header is not None for entry in entries] == [True, False, True]


def test_os_windows_jumplist_custom_destination_sources() -> None:
    lnk_guid = jumplist_module.LNK_GUID
    first_lnk = minimal_lnk()
    last_lnk = minimal_lnk()
    body = b"prefix" + lnk_guid + first_lnk + lnk_guid + last_lnk
    buffer = build_custom_destination(body, number_of_entries=2)

    envelope_size = len(buffer) - len(CUSTOM_DESTINATION_FOOTER) - len(body)
    first_offset = envelope_size + len("prefix")
    last_offset = first_offset + len(lnk_guid) + len(first_lnk)

    jumplist = CustomDestinationFile(io.BytesIO(buffer), CUSTOM_DESTINATION_FILENAME)
    entries = list(jumplist)

    assert jumplist.type == "customDestinations"
    assert jumplist.id == "590aee7bdd69b59b"
    # The two GUID markers that start a parseable LNK keep absolute file offsets.
    sources = {entry.source for entry in entries}
    assert hex(first_offset) in sources
    assert hex(last_offset) in sources


def test_os_windows_jumplist_custom_destination_skips_broken_entry() -> None:
    lnk_guid = jumplist_module.LNK_GUID
    # Build the body from explicit, non-overlapping segments so the marker
    # offsets are known up front, independent of the CLSID inside each LNK.
    first_lnk = minimal_lnk()
    corrupted = b"\xff" * 8
    last_lnk = minimal_lnk()
    body = lnk_guid + first_lnk + lnk_guid + corrupted + lnk_guid + last_lnk
    buffer = build_custom_destination(body, number_of_entries=3)

    envelope_size = len(buffer) - len(CUSTOM_DESTINATION_FOOTER) - len(body)
    first_offset = envelope_size
    corrupted_offset = first_offset + len(lnk_guid) + len(first_lnk)
    last_offset = corrupted_offset + len(lnk_guid) + len(corrupted)

    jumplist = CustomDestinationFile(io.BytesIO(buffer), CUSTOM_DESTINATION_FILENAME)
    entries = list(jumplist)

    # The two valid entries before and after the corrupted one both survive.
    valid_sources = {entry.source for entry in entries if entry.lnk.link_header is not None}
    assert hex(first_offset) in valid_sources
    assert hex(last_offset) in valid_sources
    # The corrupted marker is still reported with its own locatable source.
    all_sources = {entry.source for entry in entries}
    assert hex(corrupted_offset) in all_sources
    assert all(entry.source is not None for entry in entries)


def test_os_windows_jumplist_custom_destination_invalid_footer() -> None:
    # A version 2 / value_type 1 header is accepted, but the invalid footer is rejected.
    buffer = struct.pack("<iiii", 2, 0, 0, 1) + struct.pack("<i", 0) + b"\x00" * 4
    with pytest.raises(ValueError, match="invalid magic footer"):
        CustomDestinationFile(io.BytesIO(buffer), CUSTOM_DESTINATION_FILENAME)


def test_os_windows_jumplist_generate_records_isolates_broken_entry(
    target_win_users: Target,
    fs_win: VirtualFilesystem,
) -> None:
    user_details = target_win_users.user_details.find(username="John")
    destination_path = user_details.home_path.joinpath(
        "AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/5f7b5f1e01b83767.automaticDestinations-ms"
    )
    fs_win.map_file_fh(str(destination_path)[3:], io.BytesIO(b"dummy"))

    target_win_users.add_plugin(JumpListPlugin)
    plugin = target_win_users.jumplist
    destination = target_win_users.fs.path(str(destination_path))

    good_entry = JumpListEntry(lnk=object(), source="1.lnk")
    bad_entry = JumpListEntry(lnk=object(), source="2.lnk")
    other_good_entry = JumpListEntry(lnk=object(), source="3.lnk")

    class FakeJumpList:
        type = "automaticDestinations"

        def __init__(self, fh: object, file_name: str):
            self.application_id = file_name.split(".")[0]
            self.application_name = None

        @property
        def name(self) -> None:
            return self.application_name

        @property
        def id(self) -> str:
            return self.application_id

        def __iter__(self) -> object:
            yield good_entry
            yield bad_entry
            yield other_good_entry

    def fake_parse(target: Target, lnk: object, path: object) -> LnkRecord:
        if lnk is bad_entry.lnk:
            raise ValueError("corrupt lnk")
        return _empty_lnk_record(target, path)

    with patch.object(jumplist_module, "parse_lnk_file", side_effect=fake_parse):
        records = list(plugin._generate_records([[destination, user_details.user]], FakeJumpList))

    # The bad entry does not prevent the other records from being emitted.
    assert [record.source for record in records] == ["1.lnk", "3.lnk"]
    assert all(record.application_id == "5f7b5f1e01b83767" for record in records)
    assert all(record.type == "automaticDestinations" for record in records)
