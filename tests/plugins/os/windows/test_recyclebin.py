from __future__ import annotations

import io
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import Mock, mock_open, patch

import pytest
from dissect.util.ts import wintimestamp

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.windows.recyclebin import RecyclebinPlugin, c_recyclebin

if TYPE_CHECKING:
    from dissect.target.helpers.fsutil import TargetPath
    from dissect.target.target import Target

# SID of the user "John" as provided by the target_win_users fixture
JOHN_SID = "S-1-5-21-3263113198-3007035898-945866154-1002"
UNKNOWN_SID = "S-1-5-21-1000-2000-3000-9999"

# Distinct deletion timestamps so every volume carries its own deletion event
TS_C = 132_000_000_000_000_000
TS_D = 133_000_000_000_000_000


@pytest.fixture
def recycle_bin(tmp_path: Path) -> VirtualFilesystem:
    recycle_bin = VirtualFilesystem()
    recycle_bin.map_dir("$a_random_recycle_bin_file", tmp_path)
    return recycle_bin


def test_recycle_bin_compatibility_failed(target_win: Target) -> None:
    with pytest.raises(UnsupportedPluginError):
        RecyclebinPlugin(target_win).check_compatible()


def test_recycle_bin_compat_succeeded(target_win: Target, recycle_bin: VirtualFilesystem) -> None:
    target_win.fs.mount("C:\\$recycle.bin", recycle_bin)
    assert RecyclebinPlugin(target_win).check_compatible() is None


def test_read_recycle_bin(target_win: Target) -> None:
    mocked_file = Mock()

    mocked_file.is_file.return_value = True
    mocked_file.is_dir.return_value = False

    test_file = Mock()
    with patch.object(RecyclebinPlugin, "read_bin_file", return_value=[test_file]) as mocked_bin_file:
        assert [test_file] == list(RecyclebinPlugin(target_win).read_recycle_bin(mocked_file))
        mocked_bin_file.assert_called_once_with(mocked_file)


def test_filtered_name(target_win: Target) -> None:
    mocked_file = Mock()
    mocked_file.is_file.return_value = True
    mocked_file.is_dir.return_value = False

    mocked_file.name = "hello"

    assert list(RecyclebinPlugin(target_win).read_recycle_bin(mocked_file)) == []


def test_read_recycle_bin_directory(target_win: Target) -> None:
    mocked_dir = Mock()
    mocked_dir.is_file.return_value = False
    mocked_dir.is_dir.return_value = True
    mocked_dir.name = "SID-SOME_RANDOM_SID"

    mocked_file = Mock()
    mocked_file.is_file.return_value = True
    mocked_file.is_dir.return_value = False
    mocked_file.name = "$ihello"

    mocked_dir.iterdir.return_value = [mocked_file] * 3

    with patch.object(RecyclebinPlugin, "read_bin_file", return_value=[mocked_file]):
        data = list(RecyclebinPlugin(target_win).read_recycle_bin(mocked_dir))

        assert data == [mocked_file] * 3


@pytest.mark.parametrize(
    ("version_number", "expected_header"),
    [
        (b"\x00" * 8, "header_v1"),
        (b"\x01" * 8, "header_v1"),
        (b"\x02" + b"\x00" * 7, "header_v2"),
    ],
)
def test_parse_header(target_win: Target, version_number: bytes, expected_header: str) -> None:
    recycle_plugin = RecyclebinPlugin(target_win)

    header = recycle_plugin.select_header(version_number)
    assert header is getattr(c_recyclebin, expected_header)


@pytest.mark.parametrize(
    "path",
    [
        "file/to/some/sid",
        "file/to/$recycle.bin/sid",
    ],
)
def test_read_bin_file_unknown(target_win: Target, path: str) -> None:
    recycle_plugin = RecyclebinPlugin(target_win)

    header_1 = c_recyclebin.header_v1(version=0, file_size=0x20, timestamp=0x20, filename="hello_world" + "\x00" * 249)

    with patch.object(Path, "open", mock_open(read_data=header_1.dumps())):
        normal_path = Path(path)

        output = next(recycle_plugin.read_bin_file(normal_path), None)

    assert output.filesize == 0x20
    assert output.path == "hello_world"


def test_reading_multiple_recyclebins(target_win: Target, recycle_bin: VirtualFilesystem) -> None:
    recycle_bin.map_file_fh("$ihello_world", io.BytesIO())

    target_win.fs.mount("C:\\$recycle.bin", recycle_bin)
    target_win.fs.mount("D:\\$recycle.bin", recycle_bin)
    target_win.add_plugin(RecyclebinPlugin)

    bin_file = Mock()
    with patch.object(RecyclebinPlugin, "read_bin_file", return_value=[bin_file]):
        recycle_bin_entries = list(target_win.recyclebin())
        assert recycle_bin_entries == [bin_file] * 2


def test_reading_deleted_directory_entries(target_win: Target, tmp_path: Path) -> None:
    """Test whether a records gets created for all the entries within a deleted directory."""
    filename = "c:\\path\\to\\hello_world\0"
    header = c_recyclebin.header_v2(version=2, file_size=0, filename_length=len(filename), filename=filename)

    tmp_path.joinpath("$Ihello_world").write_bytes(header.dumps())
    tmp_path.joinpath("$Rhello_world").mkdir()
    tmp_path.joinpath("$Rhello_world/data.txt").touch()

    recycle_bin = VirtualFilesystem()
    recycle_bin.map_dir("/", tmp_path)

    target_win.fs.mount("C:\\$recycle.bin", recycle_bin)
    target_win.add_plugin(RecyclebinPlugin)

    path = target_win.fs.path(filename.strip("\0"))

    records = list(target_win.recyclebin())
    start_dir = records[0]
    assert start_dir.path == filename.rstrip("\0")
    assert start_dir.deleted_path == "c:\\$recycle.bin\\$Rhello_world"
    assert start_dir.source == "c:\\$recycle.bin\\$Ihello_world"

    file_dir = records[1]
    assert file_dir.path == str(path.joinpath("data.txt"))
    assert file_dir.deleted_path == "c:\\$recycle.bin\\$Rhello_world\\data.txt"
    assert file_dir.source == "c:\\$recycle.bin\\$Ihello_world"


def test_recyclebin_wrong_prefix(target_win: Target, recycle_bin: VirtualFilesystem) -> None:
    recycle_bin.map_file_fh("hello_world", io.BytesIO())
    target_win.fs.mount("C:\\$recycle.bin", recycle_bin)
    target_win.add_plugin(RecyclebinPlugin)

    with patch.object(RecyclebinPlugin, "read_bin_file"):
        recycle_bin_entries = list(target_win.recyclebin())
        assert recycle_bin_entries == []


@pytest.mark.parametrize(
    ("path", "expected_output"),
    [
        ("C:/$Recycle.bin/sid-data/file", "sid-data"),
        ("$Recycle.bin/sid-data/file", "sid-data"),
        ("$Recycle.bin/just_another_file", "unknown"),
        ("C:/$Recycle.bin/just_another_file", "unknown"),
    ],
)
def test_find_sid_from_path(target_win: Target, path: str, expected_output: str) -> None:
    recycle_plugin = RecyclebinPlugin(target_win)

    assert recycle_plugin.find_sid(Path(path)) == expected_output


def _ifile_bytes(original_path: str, file_size: int, timestamp: int) -> bytes:
    """Build the contents of a $I metadata file (version 2 header)."""
    filename = original_path + "\0"
    header = c_recyclebin.header_v2(
        version=2,
        file_size=file_size,
        timestamp=timestamp,
        filename_length=len(filename),
        filename=filename,
    )
    return header.dumps()


def _plant_deleted_file(
    bin_dir: Path,
    sid: str,
    name: str,
    original_path: str,
    file_size: int,
    timestamp: int,
    content: bytes | None,
) -> None:
    """Plant a ``$I<name>`` metadata file under ``bin_dir/<sid>`` and, when ``content``
    is given, its paired ``$R<name>`` content file. ``content=None`` simulates a
    deletion record whose content is missing from this volume.
    """
    sid_dir = bin_dir / sid
    sid_dir.mkdir(parents=True, exist_ok=True)
    sid_dir.joinpath(f"$I{name}").write_bytes(_ifile_bytes(original_path, file_size, timestamp))
    if content is not None:
        sid_dir.joinpath(f"$R{name}").write_bytes(content)


def _plant_deleted_dir(
    bin_dir: Path,
    sid: str,
    name: str,
    original_path: str,
    timestamp: int,
    files: dict[str, bytes],
) -> None:
    """Plant a deleted directory ``$R<name>`` containing ``files`` (relative path ->
    content) together with its ``$I<name>`` metadata file.
    """
    sid_dir = bin_dir / sid
    sid_dir.mkdir(parents=True, exist_ok=True)
    total_size = sum(len(content) for content in files.values())
    sid_dir.joinpath(f"$I{name}").write_bytes(_ifile_bytes(original_path, total_size, timestamp))
    for relative_name, content in files.items():
        deleted_entry = sid_dir.joinpath(f"$R{name}").joinpath(*relative_name.split("\\"))
        deleted_entry.parent.mkdir(parents=True, exist_ok=True)
        deleted_entry.write_bytes(content)


def _mount_recycle_bin(target: Target, drive: str, bin_dir: Path) -> None:
    """Mount ``bin_dir`` as the ``$recycle.bin`` of the given drive letter."""
    vfs = VirtualFilesystem()
    vfs.map_dir("/", bin_dir)
    target.fs.mount(f"{drive.upper()}\\$recycle.bin", vfs)


def _norm_path(record_path: object) -> str:
    """Normalize a record path field to a canonical backslash form.

    Record ``path`` fields are coerced to plain ``PurePath`` objects by flow.record.
    Depending on the Python/flow.record version, a target path can be rendered
    drive-relative (``c:foo`` instead of ``c:\\foo``). Normalize that rendering
    difference away so the assertions below compare the actual path components:
    volume letter, ``$recycle.bin`` directory, SID and file name. A cross-volume
    mix-up can never be hidden by this, only the separator after the drive letter.

    Case is preserved so the result can also be resolved against the target
    filesystem; compare with ``.lower()`` for case-insensitive assertions.
    """
    value = str(record_path).replace("/", "\\")
    if len(value) > 2 and value[1] == ":" and value[2] != "\\":
        value = f"{value[:2]}\\{value[2:]}"
    return value


def _resolve(target: Target, record_path: object) -> TargetPath:
    """Re-resolve a record path field against the target filesystem.

    Record ``path`` fields are plain path objects; resolving them again gives a
    :class:`TargetPath` that can be checked for existence and content.
    """
    return target.fs.path(_norm_path(record_path))


def test_same_named_records_across_volumes_are_not_merged(target_win_users: Target, tmp_path: Path) -> None:
    """Identically named deletion records on different volumes must each keep their own
    source, original path, deleting user and content: nothing may be stitched together
    across volumes into a single piece of evidence.
    """
    c_bin = tmp_path / "c_bin"
    d_bin = tmp_path / "d_bin"
    _plant_deleted_file(c_bin, JOHN_SID, "report.docx", "c:\\users\\john\\report.docx", 0xC0, TS_C, b"c-volume-content")
    _plant_deleted_file(d_bin, JOHN_SID, "report.docx", "d:\\data\\report.docx", 0xD0, TS_D, b"d-volume-content")

    _mount_recycle_bin(target_win_users, "c:", c_bin)
    _mount_recycle_bin(target_win_users, "d:", d_bin)
    target_win_users.add_plugin(RecyclebinPlugin)

    records = list(target_win_users.recyclebin())
    assert len(records) == 2

    expected = {
        "c": ("c:\\users\\john\\report.docx", 0xC0, TS_C, b"c-volume-content"),
        "d": ("d:\\data\\report.docx", 0xD0, TS_D, b"d-volume-content"),
    }
    seen_volumes = set()
    for record in records:
        source = _norm_path(record.source).lower()
        volume = source[0]
        seen_volumes.add(volume)
        original_path, file_size, timestamp, content = expected[volume]

        # the metadata record keeps its own traceable source on its own volume
        assert source == f"{volume}:\\$recycle.bin\\{JOHN_SID.lower()}\\$ireport.docx"
        assert _resolve(target_win_users, record.source).exists()
        # the original path is parsed from this record's own $I file
        assert _norm_path(record.path).lower() == original_path
        assert record.filesize == file_size
        # the deleted content is resolved on the same volume as the metadata
        deleted_path = _norm_path(record.deleted_path).lower()
        assert deleted_path == f"{volume}:\\$recycle.bin\\{JOHN_SID.lower()}\\$rreport.docx"
        assert deleted_path[0] == volume
        # the content attached to the record comes from the same volume
        assert _resolve(target_win_users, record.deleted_path).read_bytes() == content
        # deletion time and user attribution travel with the record
        assert record.ts == wintimestamp(timestamp)
        assert record.username == "John"
        assert record.user_id == JOHN_SID

    assert seen_volumes == {"c", "d"}
    # the two records must not have collapsed into one merged piece of evidence
    assert len({_norm_path(record.source).lower() for record in records}) == 2
    assert len({_norm_path(record.deleted_path).lower() for record in records}) == 2


def test_missing_content_is_not_backfilled_from_other_volume(target_win_users: Target, tmp_path: Path) -> None:
    """A $I record whose $R content is missing must remain traceable to its own source;
    the gap must not be filled with a same-named file from another volume.
    """
    c_bin = tmp_path / "c_bin"
    d_bin = tmp_path / "d_bin"
    _plant_deleted_file(c_bin, JOHN_SID, "shared.txt", "c:\\users\\john\\shared.txt", 0xC1, TS_C, b"c-shared-content")
    # same-named deletion record on D: but its $R content file is gone
    _plant_deleted_file(d_bin, JOHN_SID, "shared.txt", "d:\\data\\shared.txt", 0xD1, TS_D, content=None)

    _mount_recycle_bin(target_win_users, "c:", c_bin)
    _mount_recycle_bin(target_win_users, "d:", d_bin)
    target_win_users.add_plugin(RecyclebinPlugin)

    records = list(target_win_users.recyclebin())
    assert len(records) == 2

    by_volume = {_norm_path(record.source).lower()[0]: record for record in records}

    c_record = by_volume["c"]
    assert _norm_path(c_record.deleted_path).lower() == f"c:\\$recycle.bin\\{JOHN_SID.lower()}\\$rshared.txt"
    assert _resolve(target_win_users, c_record.deleted_path).read_bytes() == b"c-shared-content"

    d_record = by_volume["d"]
    # the record survives the missing content and keeps its own metadata
    assert _norm_path(d_record.source).lower() == f"d:\\$recycle.bin\\{JOHN_SID.lower()}\\$ishared.txt"
    assert _resolve(target_win_users, d_record.source).exists()
    assert _norm_path(d_record.path).lower() == "d:\\data\\shared.txt"
    assert d_record.filesize == 0xD1
    assert d_record.ts == wintimestamp(TS_D)
    # its deleted_path still points at its own volume ...
    assert _norm_path(d_record.deleted_path).lower() == f"d:\\$recycle.bin\\{JOHN_SID.lower()}\\$rshared.txt"
    # ... and the missing content is not substituted with the same-named file from C:
    assert not _resolve(target_win_users, d_record.deleted_path).exists()

    # exactly one record carries existing content: no cross-volume borrowing happened
    assert sum(1 for record in records if _resolve(target_win_users, record.deleted_path).exists()) == 1


def test_deleted_directory_entries_stay_with_their_deletion_event(target_win_users: Target, tmp_path: Path) -> None:
    """Entries expanded from a deleted directory belong to the deletion event of their
    own volume: same-named deleted directories on other volumes must not absorb them.
    """
    c_bin = tmp_path / "c_bin"
    d_bin = tmp_path / "d_bin"
    _plant_deleted_dir(
        c_bin,
        JOHN_SID,
        "reports",
        "c:\\users\\john\\reports",
        TS_C,
        {"a.txt": b"c-a-content", "sub\\b.txt": b"c-b-content"},
    )
    _plant_deleted_dir(
        d_bin,
        JOHN_SID,
        "reports",
        "d:\\reports",
        TS_D,
        {"a.txt": b"d-a-content"},
    )

    _mount_recycle_bin(target_win_users, "c:", c_bin)
    _mount_recycle_bin(target_win_users, "d:", d_bin)
    target_win_users.add_plugin(RecyclebinPlugin)

    records = list(target_win_users.recyclebin())
    # C: deletion event -> directory + a.txt + sub + sub\\b.txt; D: event -> directory + a.txt
    assert len(records) == 6

    expected = {
        "c": ("c:\\users\\john\\reports", TS_C, {"a.txt": b"c-a-content", "sub\\b.txt": b"c-b-content"}),
        "d": ("d:\\reports", TS_D, {"a.txt": b"d-a-content"}),
    }
    by_source: dict[str, list] = {}
    for record in records:
        by_source.setdefault(_norm_path(record.source).lower(), []).append(record)

    assert set(by_source) == {
        f"c:\\$recycle.bin\\{JOHN_SID.lower()}\\$ireports",
        f"d:\\$recycle.bin\\{JOHN_SID.lower()}\\$ireports",
    }

    for source, group in by_source.items():
        volume = source[0]
        original_dir, timestamp, files = expected[volume]
        deleted_dir = f"{volume}:\\$recycle.bin\\{JOHN_SID.lower()}\\$rreports"

        # every expanded entry still belongs to the original deletion event:
        # same source $I file, same deletion time, same deleting user
        for record in group:
            assert record.ts == wintimestamp(timestamp)
            assert record.username == "John"
            assert record.user_id == JOHN_SID
            # nothing points at the other volume
            assert _norm_path(record.deleted_path).lower().startswith(deleted_dir)
            assert _norm_path(record.path).lower().startswith(original_dir)

        parent = next(record for record in group if _norm_path(record.deleted_path).lower() == deleted_dir)
        assert _norm_path(parent.path).lower() == original_dir

        expanded = {
            _norm_path(record.path).lower()[len(original_dir) + 1 :]: record for record in group if record is not parent
        }
        expected_expanded = {"a.txt", "sub", "sub\\b.txt"} if volume == "c" else {"a.txt"}
        assert set(expanded) == expected_expanded

        # the content behind each expanded entry comes from the same volume as the event
        for relative_name, content in files.items():
            record = expanded[relative_name]
            assert _resolve(target_win_users, record.deleted_path).read_bytes() == content
            assert record.filesize == len(content)


def test_record_with_unknown_sid_keeps_its_source(target_win_users: Target, tmp_path: Path) -> None:
    """A deletion record from a SID that resolves to no known user still yields a
    traceable record: source and deleted_path remain intact, user fields stay empty
    instead of being attributed to another user.
    """
    c_bin = tmp_path / "c_bin"
    _plant_deleted_file(c_bin, UNKNOWN_SID, "secret.txt", "c:\\users\\unknown\\secret.txt", 0x42, TS_C, b"top-secret")

    _mount_recycle_bin(target_win_users, "c:", c_bin)
    target_win_users.add_plugin(RecyclebinPlugin)

    records = list(target_win_users.recyclebin())
    assert len(records) == 1

    record = records[0]
    assert _norm_path(record.source).lower() == f"c:\\$recycle.bin\\{UNKNOWN_SID.lower()}\\$isecret.txt"
    assert _norm_path(record.deleted_path).lower() == f"c:\\$recycle.bin\\{UNKNOWN_SID.lower()}\\$rsecret.txt"
    assert _norm_path(record.path).lower() == "c:\\users\\unknown\\secret.txt"
    assert _resolve(target_win_users, record.deleted_path).read_bytes() == b"top-secret"
    assert record.username is None
    assert record.user_id is None
