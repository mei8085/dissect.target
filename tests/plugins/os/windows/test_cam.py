from __future__ import annotations

import datetime
import sqlite3
from typing import TYPE_CHECKING

import pytest
from dissect.util.ts import wintimestamp

from dissect.target.helpers.regutil import VirtualKey, VirtualValue
from dissect.target.plugins.os.windows.cam import CamPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    import pathlib

    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.helpers.regutil import VirtualHive
    from dissect.target.target import Target


def test_cam_history(target_win_users: Target, hive_hklm: VirtualHive, fs_win: VirtualFilesystem) -> None:
    fs_win.map_file(
        "ProgramData/Microsoft/Windows/CapabilityAccessManager/CapabilityAccessManager.db",
        absolute_path("_data/plugins/os/windows/cam/CapabilityAccessManager.db"),
    )

    hklm_cam_key = VirtualKey(
        hive_hklm,
        "Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\CapabilityUsageHistory",
    )

    database_root_value = "C:\\ProgramData\\Microsoft\\Windows\\CapabilityAccessManager"
    hklm_cam_key.add_value("DatabaseRoot", VirtualValue(hive_hklm, "DatabaseRoot", database_root_value))

    hive_hklm.map_key(hklm_cam_key.path, hklm_cam_key)

    target_win_users.add_plugin(CamPlugin)
    results = list(target_win_users.cam())

    assert len(results) == 3

    # Record windows/cam/usagehistory - NonPackagedUsageHistory
    assert results[0].last_used_time_stop == wintimestamp(133885054906926593)
    assert results[0].last_used_time_start == wintimestamp(133885044556858623)
    assert results[0].duration == 1035
    assert results[0].package_type == "NonPackagedUsageHistory"
    assert results[0].capability == "microphone"
    assert results[0].file_id == "0000f0bfca16305374262ad1919c258deba64fc25006"
    assert results[0].file_id_hash.sha1 == "f0bfca16305374262ad1919c258deba64fc25006"
    assert results[0].access_blocked == "0"
    assert results[0].program_id == "00001495bc9d3674a3db3bbed7de63ca0f920000ffff"
    assert results[0].package_family_name is None
    assert results[0].access_guid is None
    assert results[0].label == "2"
    assert results[0].app_name == "Microsoft Edge"
    assert results[0].binary_full_path == "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
    assert results[0].service_name is None
    assert results[0].username is None

    # Record windows/cam/usagehistory - NonPackagedUsageHistory
    assert results[1].last_used_time_stop == wintimestamp(133884984261774039)
    assert results[1].last_used_time_start == wintimestamp(133884984204276055)
    assert results[1].duration == 5
    assert results[1].package_type == "PackagedUsageHistory"
    assert results[1].capability == "microphone"
    assert results[1].file_id is None
    assert results[1].file_id_hash.sha1 is None
    assert results[1].access_blocked == "0"
    assert results[1].program_id is None
    assert results[1].package_family_name == "Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe"
    assert results[1].app_name == "Sound Recorder"
    assert results[1].access_guid is None
    assert results[1].label == "2"
    assert results[1].app_name == "Sound Recorder"
    assert results[1].binary_full_path is None
    assert results[1].service_name is None
    assert results[1].username is None

    # Record windows/cam/identityrelationshiphistory - NonPackagedIdentityRelationship
    assert results[2].last_observed_time == wintimestamp(133892048101847846)
    assert results[2].file_id == "0000565c728f1a97551d85db2e788c69e0d8a18ea777"
    assert results[2].file_id_hash.sha1 == "565c728f1a97551d85db2e788c69e0d8a18ea777"
    assert results[2].program_id == "0000d44ffb9f3c146e6da82376ed56489aff0000ffff"
    assert results[2].binary_full_path == "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"

    # Record windows/cam/globalprompthistory - NonPackagedGlobalPromptHistory
    # No test data for this record type.


def test_cam_registry(target_win_users: Target, hive_hku: VirtualHive, hive_hklm: VirtualHive) -> None:
    hku_cam_key = VirtualKey(
        hive_hku,
        "Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam",
    )

    hklm_cam_key = VirtualKey(
        hive_hklm,
        "Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone",
    )

    microsoft_camera_key = VirtualKey(
        hive_hku, f"{hive_hku}\\{hku_cam_key.path}\\Microsoft.WindowsCamera_8wekyb3d8bbwe"
    )
    microsoft_camera_key.add_value("LastUsedTimeStart", VirtualValue(hive_hku, "LastUsedTimeStart", 133784711366495858))
    microsoft_camera_key.add_value("LastUsedTimeStop", VirtualValue(hive_hku, "LastUsedTimeStop", 133784711515887950))

    firefox_key = VirtualKey(
        hive_hku, f"{hive_hku}\\{hku_cam_key.path}\\NonPackaged\\C:#Program Files#Mozilla Firefox#firefox.exe"
    )
    firefox_key.add_value("LastUsedTimeStart", VirtualValue(hive_hku, "LastUsedTimeStart", 133788466426086184))
    firefox_key.add_value("LastUsedTimeStop", VirtualValue(hive_hku, "LastUsedTimeStop", 133788466774490036))

    nonpackaged_key = VirtualKey(hive_hku, f"{hive_hku}\\{hku_cam_key.path}\\NonPackaged")
    nonpackaged_key.add_subkey("C:#Program Files#Mozilla Firefox#firefox.exe", firefox_key)

    python_key = VirtualKey(
        hive_hklm, f"{hive_hklm}\\{hklm_cam_key.path}\\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0"
    )
    python_key.add_value("LastUsedTimeStart", VirtualValue(hive_hklm, "LastUsedTimeStart", 133788466426086163))
    python_key.add_value("LastUsedTimeStop", VirtualValue(hive_hklm, "LastUsedTimeStop", 133788466774490044))

    hku_cam_key.add_subkey(microsoft_camera_key.name, microsoft_camera_key)
    hku_cam_key.add_subkey(nonpackaged_key.name, nonpackaged_key)
    hklm_cam_key.add_subkey(python_key.name, python_key)

    hive_hku.map_key(hku_cam_key.path, hku_cam_key)
    hive_hklm.map_key(hklm_cam_key.path, hklm_cam_key)

    target_win_users.add_plugin(CamPlugin)
    results = list(target_win_users.cam())

    assert len(results) == 3
    assert results[0].device == "webcam"
    assert results[0].app_name == "Microsoft.WindowsCamera_8wekyb3d8bbwe"
    assert results[0].path is None
    assert results[0].last_started == wintimestamp(133784711366495858)
    assert results[0].last_stopped == wintimestamp(133784711515887950)
    assert results[1].device == "webcam"
    assert results[1].app_name == "C:#Program Files#Mozilla Firefox#firefox.exe"
    assert results[1].path == "C:\\Program Files\\Mozilla Firefox\\firefox.exe"
    assert results[1].last_started == wintimestamp(133788466426086184)
    assert results[1].last_stopped == wintimestamp(133788466774490036)
    assert results[2].device == "microphone"
    assert results[2].app_name == "PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0"
    assert results[2].path is None
    assert results[2].last_started == wintimestamp(133788466426086163)
    assert results[2].last_stopped == wintimestamp(133788466774490044)


# --- Capability access history integration tests -------------------------------------------------------
#
# The Capability Access Manager records application use of devices in two places: the ConsentStore registry
# keys and the CapabilityAccessManager database. Both sources are exercised below against one another so that
# times, user attribution, application paths and the meaning of an access interval stay comparable.

# SID of the user "John" as provided by the ``target_win_users`` fixture.
JOHN_SID = "S-1-5-21-3263113198-3007035898-945866154-1002"
# A SID that is present in the capability database but resolves to no known user.
UNKNOWN_SID = "S-1-5-21-1000-2000-3000-9999"

CONSENT_STORE = "Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore"
CAPABILITY_DB_ROOT = "C:\\ProgramData\\Microsoft\\Windows\\CapabilityAccessManager"
CAPABILITY_DB_KEY = "Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\CapabilityUsageHistory"

USAGE_RECORD = "windows/cam/usagehistory"
IDENTITY_RECORD = "windows/cam/identityrelationshiphistory"
PROMPT_RECORD = "windows/cam/globalprompthistory"

WIN_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


def _ticks(moment: datetime.datetime) -> int:
    """Convert an aware datetime to the Windows FILETIME (100 ns since 1601) integer used on disk."""
    delta = moment - WIN_EPOCH
    return (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


def _utc(*args: int) -> datetime.datetime:
    return datetime.datetime(*args, tzinfo=datetime.timezone.utc)


# Fixed moments; every expected value below is derived from them, never from the current time.
MIC_START = _utc(2024, 5, 1, 12, 0, 0)
MIC_STOP = _utc(2024, 5, 1, 12, 17, 15)  # 1035 seconds
CAM_START = _utc(2024, 5, 2, 8, 0, 0)  # unfinished interval: the stop time was never recorded
PACKAGED_START = _utc(2024, 5, 3, 9, 0, 0)
PACKAGED_STOP = _utc(2024, 5, 3, 9, 0, 5)  # 5 seconds
PROMPT_TIME = _utc(2024, 5, 4, 10, 0, 0)
OBSERVED_TIME = _utc(2024, 5, 5, 12, 0, 0)

REGISTRY_CAM_START = _utc(2024, 6, 2, 9, 0, 0)
REGISTRY_CAM_STOP = _utc(2024, 6, 2, 9, 3, 20)  # 200 seconds
REGISTRY_NP_START = _utc(2024, 6, 2, 10, 0, 0)
REGISTRY_NP_STOP = _utc(2024, 6, 2, 10, 0, 5)  # 5 seconds
REGISTRY_OPEN_START = _utc(2024, 6, 3, 11, 0, 0)  # unfinished interval: no stop value recorded
REGISTRY_MIC_START = _utc(2024, 6, 1, 7, 0, 0)
REGISTRY_MIC_STOP = _utc(2024, 6, 1, 7, 30, 0)  # 1800 seconds

NONPACKAGED_CAMERA_KEY = "C:#Program Files#Contoso#camera.exe"
NONPACKAGED_CAMERA_PATH = "C:\\Program Files\\Contoso\\camera.exe"

# Table layout of the CapabilityAccessManager database as written by Windows 11.
CAPABILITY_DB_SCHEMA = """
CREATE TABLE NonPackagedUsageHistory(ID INTEGER PRIMARY KEY NOT NULL,LastUsedTimeStart INTEGER NOT NULL,
  LastUsedTimeStop INTEGER NOT NULL,AccessBlocked INTEGER NOT NULL,Capability INTEGER NOT NULL,FileID INTEGER NOT NULL,
  ProgramID INTEGER NOT NULL,BinaryFullPath INTEGER NOT NULL,UserSid INTEGER NOT NULL,AppName INTEGER NOT NULL,
  ServiceName INTEGER NOT NULL DEFAULT '0',AccessGUID INTEGER NOT NULL,Label INTEGER NOT NULL);
CREATE TABLE PackagedUsageHistory(ID INTEGER PRIMARY KEY NOT NULL,LastUsedTimeStart INTEGER NOT NULL,
  LastUsedTimeStop INTEGER NOT NULL,AccessBlocked INTEGER NOT NULL,Capability INTEGER NOT NULL,
  PackageFamilyName INTEGER NOT NULL,UserSid INTEGER NOT NULL,AccessGUID INTEGER NOT NULL,Label INTEGER NOT NULL,
  AppName INTEGER NOT NULL);
CREATE TABLE NonPackagedIdentityRelationship(ID INTEGER PRIMARY KEY NOT NULL,BinaryFullPath INTEGER NOT NULL,
  FileID INTEGER NOT NULL,ProgramID INTEGER NOT NULL,LastObservedTime INTEGER NOT NULL);
CREATE TABLE NonPackagedGlobalPromptHistory(ID INTEGER PRIMARY KEY NOT NULL,ShownTime INTEGER NOT NULL,
  Capability INTEGER NOT NULL,FileID INTEGER NOT NULL,ProgramID INTEGER NOT NULL,UserSid INTEGER NOT NULL);
CREATE TABLE Capabilities(ID INTEGER PRIMARY KEY NOT NULL,StringValue TEXT COLLATE NOCASE NOT NULL);
CREATE TABLE PackageFamilyNames(ID INTEGER PRIMARY KEY NOT NULL,StringValue TEXT COLLATE NOCASE NOT NULL);
CREATE TABLE BinaryFullPaths(ID INTEGER PRIMARY KEY NOT NULL,StringValue TEXT COLLATE NOCASE NOT NULL);
CREATE TABLE Users(ID INTEGER PRIMARY KEY NOT NULL,StringValue TEXT COLLATE NOCASE NOT NULL);
CREATE TABLE FileIDs(ID INTEGER PRIMARY KEY NOT NULL,StringValue TEXT COLLATE NOCASE NOT NULL);
CREATE TABLE ProgramIDs(ID INTEGER PRIMARY KEY NOT NULL,StringValue TEXT COLLATE NOCASE NOT NULL);
CREATE TABLE AccessGUIDs(ID INTEGER PRIMARY KEY NOT NULL,StringValue TEXT COLLATE NOCASE NOT NULL);
CREATE TABLE AppNames(ID INTEGER PRIMARY KEY NOT NULL,StringValue TEXT COLLATE NOCASE NOT NULL);
CREATE TABLE ServiceNames(ID INTEGER PRIMARY KEY NOT NULL,StringValue TEXT COLLATE NOCASE NOT NULL);
"""


def _build_capability_db(path: pathlib.Path) -> None:
    """Write a CapabilityAccessManager database with microphone and camera usage rows.

    The rows mix finished intervals with a row whose stop time is still zero, which is how Windows stores an
    access interval that has not ended yet.
    """
    connection = sqlite3.connect(path)
    try:
        connection.executescript(CAPABILITY_DB_SCHEMA)
        connection.executemany("INSERT INTO Users VALUES (?, ?)", [(1, JOHN_SID), (2, UNKNOWN_SID)])
        connection.executemany("INSERT INTO Capabilities VALUES (?, ?)", [(1, "microphone"), (2, "webcam")])
        connection.executemany(
            "INSERT INTO FileIDs VALUES (?, ?)",
            [
                (1, "0000f0bfca16305374262ad1919c258deba64fc25006"),
                (2, "0000565c728f1a97551d85db2e788c69e0d8a18ea777"),
            ],
        )
        connection.executemany(
            "INSERT INTO ProgramIDs VALUES (?, ?)",
            [
                (1, "00001495bc9d3674a3db3bbed7de63ca0f920000ffff"),
                (2, "0000d44ffb9f3c146e6da82376ed56489aff0000ffff"),
            ],
        )
        connection.executemany(
            "INSERT INTO BinaryFullPaths VALUES (?, ?)",
            [
                (1, "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"),
                (2, NONPACKAGED_CAMERA_PATH),
            ],
        )
        connection.executemany(
            "INSERT INTO AppNames VALUES (?, ?)",
            [(1, "Microsoft Edge"), (2, "Camera"), (3, "Sound Recorder")],
        )
        connection.executemany(
            "INSERT INTO PackageFamilyNames VALUES (?, ?)",
            [
                (1, "Microsoft.WindowsCamera_8wekyb3d8bbwe"),
                (2, "Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe"),
            ],
        )
        connection.executemany("INSERT INTO ServiceNames VALUES (?, ?)", [(1, "webthreatdefusersvc_110621")])
        connection.executemany("INSERT INTO AccessGUIDs VALUES (?, ?)", [(1, "{6D809377-6AF0-444B-8957-A3773F02200E}")])
        # Non-packaged microphone usage: finished interval, attributed to John.
        connection.execute(
            "INSERT INTO NonPackagedUsageHistory VALUES (1, ?, ?, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2)",
            (_ticks(MIC_START), _ticks(MIC_STOP)),
        )
        # Non-packaged camera usage: unfinished interval (stop time 0), attributed to the unknown SID.
        connection.execute(
            "INSERT INTO NonPackagedUsageHistory VALUES (2, ?, 0, 1, 2, 2, 2, 2, 2, 2, 0, 0, 2)",
            (_ticks(CAM_START),),
        )
        # Packaged camera and microphone usage: finished intervals, attributed to John.
        connection.execute(
            "INSERT INTO PackagedUsageHistory VALUES (1, ?, ?, 0, 2, 1, 1, 0, 2, 2)",
            (_ticks(PACKAGED_START), _ticks(PACKAGED_STOP)),
        )
        connection.execute(
            "INSERT INTO PackagedUsageHistory VALUES (2, ?, ?, 0, 1, 2, 1, 0, 2, 3)",
            (_ticks(PACKAGED_START), _ticks(PACKAGED_STOP)),
        )
        connection.execute(
            "INSERT INTO NonPackagedIdentityRelationship VALUES (1, 1, 1, 1, ?)",
            (_ticks(OBSERVED_TIME),),
        )
        # A permission prompt that was shown is not an access interval.
        connection.execute(
            "INSERT INTO NonPackagedGlobalPromptHistory VALUES (1, ?, 2, 2, 2, 1)",
            (_ticks(PROMPT_TIME),),
        )
        connection.commit()
    finally:
        connection.close()


def _map_capability_db(hive_hklm: VirtualHive, fs_win: VirtualFilesystem, path: pathlib.Path) -> None:
    """Map a capability database and the registry value that points the plugin at it."""
    key = VirtualKey(hive_hklm, CAPABILITY_DB_KEY)
    key.add_value("DatabaseRoot", VirtualValue(hive_hklm, "DatabaseRoot", CAPABILITY_DB_ROOT))
    hive_hklm.map_key(CAPABILITY_DB_KEY, key)

    fs_win.map_file("ProgramData/Microsoft/Windows/CapabilityAccessManager/CapabilityAccessManager.db", path)


def _attribute_user_hive(target_win_users: Target, hive_hku: VirtualHive) -> None:
    """Tie the fixture's HKEY_USERS hive of John to John.

    ``target_win_users`` adds the hive under ``HKEY_USERS\\<sid>`` but does not record which user owns it; the
    registry plugin normally fills that mapping while loading ``ntuser.dat``.
    """
    details = target_win_users.user_details.find(sid=JOHN_SID)
    hive_hku.filepath = details.home_path.joinpath("ntuser.dat")
    target_win_users.registry._hives_to_users[hive_hku] = details


def _consent_app(hive: VirtualHive, device: str, name: str, *, in_nonpackaged: bool = False) -> VirtualKey:
    """Create an application key below a ConsentStore device key, optionally under ``NonPackaged``."""
    parent = f"{CONSENT_STORE}\\{device}"
    if in_nonpackaged:
        parent = f"{parent}\\NonPackaged"

    app_key = VirtualKey(hive, f"{parent}\\{name}")
    hive.make_keys(parent).add_subkey(name, app_key)
    return app_key


def _set_interval(key: VirtualKey, hive: VirtualHive, start: datetime.datetime, stop: datetime.datetime | None) -> None:
    key.add_value("LastUsedTimeStart", VirtualValue(hive, "LastUsedTimeStart", _ticks(start)))
    if stop is not None:
        key.add_value("LastUsedTimeStop", VirtualValue(hive, "LastUsedTimeStop", _ticks(stop)))


def _records_by_type(records: list, record_type: str) -> list:
    return [record for record in records if record._desc.name == record_type]


def _comparable(record: object) -> dict:
    """Return a record's evidence fields in a form that compares reliably across two reads.

    ``digest`` values do not compare equal across two reads even when they carry the same hash, so they are
    replaced by their plain hash strings. The moment a record object was generated is not evidence.
    """
    values = {name: value for name, value in record._asdict().items() if name not in ("_generated", "_source")}
    for name, value in values.items():
        if hasattr(value, "sha1") and hasattr(value, "md5"):
            values[name] = (value.md5, value.sha1, value.sha256)
    return values


def test_cam_registry_device_user_and_path_attribution(
    target_win_users: Target, hive_hklm: VirtualHive, hive_hku: VirtualHive
) -> None:
    """Every registry record keeps the device, user and application path of its own ConsentStore key.

    A machine-wide application has no user, a packaged application of the current user is attributed through
    the hive that owns its key, and a non-packaged key name is decoded into the executable path while the
    recorded application name stays the key name.
    """
    _attribute_user_hive(target_win_users, hive_hku)

    machine_app = _consent_app(hive_hklm, "microphone", "Windows-Test-Service")
    _set_interval(machine_app, hive_hklm, REGISTRY_MIC_START, REGISTRY_MIC_STOP)

    packaged_app = _consent_app(hive_hku, "webcam", "Microsoft.WindowsCamera_8wekyb3d8bbwe")
    _set_interval(packaged_app, hive_hku, REGISTRY_CAM_START, REGISTRY_CAM_STOP)

    nonpackaged_app = _consent_app(hive_hku, "webcam", NONPACKAGED_CAMERA_KEY, in_nonpackaged=True)
    _set_interval(nonpackaged_app, hive_hku, REGISTRY_NP_START, REGISTRY_NP_STOP)

    target_win_users.add_plugin(CamPlugin)
    records = list(target_win_users.cam.registry())
    assert len(records) == 3

    by_app = {record.app_name: record for record in records}
    assert set(by_app) == {"Windows-Test-Service", "Microsoft.WindowsCamera_8wekyb3d8bbwe", NONPACKAGED_CAMERA_KEY}

    machine_record = by_app["Windows-Test-Service"]
    assert machine_record.device == "microphone"
    assert machine_record.path is None
    assert machine_record.username is None
    assert machine_record.user_id is None

    packaged_record = by_app["Microsoft.WindowsCamera_8wekyb3d8bbwe"]
    assert packaged_record.device == "webcam"
    assert packaged_record.path is None
    assert packaged_record.username == "John"
    assert packaged_record.user_id == JOHN_SID

    nonpackaged_record = by_app[NONPACKAGED_CAMERA_KEY]
    assert nonpackaged_record.device == "webcam"
    assert nonpackaged_record.path == NONPACKAGED_CAMERA_PATH
    assert nonpackaged_record.username == "John"
    assert nonpackaged_record.user_id == JOHN_SID
    # the key path names the exact registry location the record came from
    assert nonpackaged_record.regf_key_path.endswith(f"webcam\\NonPackaged\\{NONPACKAGED_CAMERA_KEY}")


def test_cam_registry_finished_interval_duration(
    target_win_users: Target, hive_hklm: VirtualHive, hive_hku: VirtualHive
) -> None:
    """A finished registry interval reports its exact start, stop and elapsed seconds for both devices."""
    _attribute_user_hive(target_win_users, hive_hku)

    camera = _consent_app(hive_hku, "webcam", "Microsoft.WindowsCamera_8wekyb3d8bbwe")
    _set_interval(camera, hive_hku, REGISTRY_CAM_START, REGISTRY_CAM_STOP)
    microphone = _consent_app(hive_hklm, "microphone", "Windows-Test-Service")
    _set_interval(microphone, hive_hklm, REGISTRY_MIC_START, REGISTRY_MIC_STOP)

    target_win_users.add_plugin(CamPlugin)
    records = {record.device: record for record in target_win_users.cam.registry()}

    assert records["webcam"].last_started == wintimestamp(_ticks(REGISTRY_CAM_START))
    assert records["webcam"].last_stopped == wintimestamp(_ticks(REGISTRY_CAM_STOP))
    assert records["webcam"].duration == 200

    assert records["microphone"].last_started == wintimestamp(_ticks(REGISTRY_MIC_START))
    assert records["microphone"].last_stopped == wintimestamp(_ticks(REGISTRY_MIC_STOP))
    assert records["microphone"].duration == 1800


def test_cam_registry_permission_only_entry_is_not_access(target_win_users: Target, hive_hku: VirtualHive) -> None:
    """An entry that only allows a capability is not evidence that the capability was accessed.

    The permission lives on the ConsentStore device key, and an application key can exist without ever
    recording a use. Such an entry may still be reported for traceability, but it must not carry a start, stop
    or duration, and it must not borrow the times of a neighbouring application.
    """
    _attribute_user_hive(target_win_users, hive_hku)

    device_key = hive_hku.make_keys(f"{CONSENT_STORE}\\webcam")
    device_key.add_value("Value", VirtualValue(hive_hku, "Value", "Allow"))

    permitted_app = _consent_app(hive_hku, "webcam", "Contoso.Permitted_8wekyb3d8bbwe")
    permitted_app.add_value("Value", VirtualValue(hive_hku, "Value", "Allow"))

    used_app = _consent_app(hive_hku, "webcam", "Contoso.Used_8wekyb3d8bbwe")
    _set_interval(used_app, hive_hku, REGISTRY_CAM_START, REGISTRY_CAM_STOP)

    target_win_users.add_plugin(CamPlugin)
    records = {record.app_name: record for record in target_win_users.cam.registry()}
    assert set(records) == {"Contoso.Permitted_8wekyb3d8bbwe", "Contoso.Used_8wekyb3d8bbwe"}

    permitted = records["Contoso.Permitted_8wekyb3d8bbwe"]
    assert permitted.device == "webcam"
    assert permitted.last_started is None
    assert permitted.last_stopped is None
    assert permitted.duration is None

    used = records["Contoso.Used_8wekyb3d8bbwe"]
    assert used.last_started == wintimestamp(_ticks(REGISTRY_CAM_START))
    assert used.last_stopped == wintimestamp(_ticks(REGISTRY_CAM_STOP))
    assert used.duration == 200

    # only the application that recorded a use carries an access interval
    with_start = [record for record in records.values() if record.last_started is not None]
    assert [record.app_name for record in with_start] == ["Contoso.Used_8wekyb3d8bbwe"]


def test_cam_registry_unfinished_interval_keeps_open_identity(target_win_users: Target, hive_hku: VirtualHive) -> None:
    """An application that started using the webcam without recording a stop keeps an open interval.

    The record must not invent a stop time or a duration from the current time, and the start time must stay
    the one that was recorded.
    """
    _attribute_user_hive(target_win_users, hive_hku)

    open_app = _consent_app(hive_hku, "webcam", "Contoso.Live_8wekyb3d8bbwe")
    _set_interval(open_app, hive_hku, REGISTRY_OPEN_START, None)

    target_win_users.add_plugin(CamPlugin)
    records = list(target_win_users.cam.registry())
    assert len(records) == 1

    record = records[0]
    assert record.device == "webcam"
    assert record.last_started == wintimestamp(_ticks(REGISTRY_OPEN_START))
    # the interval is still open: no stop moment and no elapsed time are claimed
    assert record.last_stopped is None
    assert record.duration is None


@pytest.mark.xfail(reason="Known defect: a zero stop value becomes a 1601 stop time with a bogus duration")
def test_cam_registry_zero_stop_time_is_open_interval(target_win_users: Target, hive_hku: VirtualHive) -> None:
    """An unfinished registry interval must keep its open identity when the stop value is zero."""
    _attribute_user_hive(target_win_users, hive_hku)

    open_app = _consent_app(hive_hku, "webcam", "Contoso.Live_8wekyb3d8bbwe")
    open_app.add_value("LastUsedTimeStart", VirtualValue(hive_hku, "LastUsedTimeStart", _ticks(REGISTRY_OPEN_START)))
    open_app.add_value("LastUsedTimeStop", VirtualValue(hive_hku, "LastUsedTimeStop", 0))

    target_win_users.add_plugin(CamPlugin)
    record = next(iter(target_win_users.cam.registry()))

    assert record.last_stopped is None
    assert record.duration in (None, 0)


@pytest.mark.xfail(reason="Known defect: registry durations drop whole days, unlike the database source")
def test_cam_registry_long_interval_reports_full_elapsed_seconds(
    target_win_users: Target, hive_hku: VirtualHive
) -> None:
    """A finished interval longer than a day must report all elapsed seconds.

    The database source subtracts both timestamps, so a 25 hour interval is 90000 seconds there. The registry
    source must give the same answer instead of truncating the interval to its remainder within a day.
    """
    _attribute_user_hive(target_win_users, hive_hku)

    long_app = _consent_app(hive_hku, "webcam", "Contoso.LongRunning_8wekyb3d8bbwe")
    start = _utc(2024, 6, 5, 0, 0, 0)
    stop = _utc(2024, 6, 6, 1, 0, 0)
    _set_interval(long_app, hive_hku, start, stop)

    target_win_users.add_plugin(CamPlugin)
    record = next(iter(target_win_users.cam.registry()))

    assert (wintimestamp(_ticks(stop)) - wintimestamp(_ticks(start))).total_seconds() == 90000
    assert record.duration == 90000


def test_cam_history_time_user_and_path_attribution(
    target_win_users: Target,
    fs_win: VirtualFilesystem,
    hive_hklm: VirtualHive,
    tmp_path: pathlib.Path,
) -> None:
    """Database usage records carry the times, user and application path of their own row.

    Microphone and camera rows resolve their capability, user SID, executable path, package family, service and
    access GUID through the database's own context tables. A packaged row has no executable path and a
    non-packaged row has no package family; neither may take the other's values.
    """
    database = tmp_path / "CapabilityAccessManager.db"
    _build_capability_db(database)
    _map_capability_db(hive_hklm, fs_win, database)

    target_win_users.add_plugin(CamPlugin)
    records = _records_by_type(list(target_win_users.cam.history()), USAGE_RECORD)
    assert len(records) == 4

    by_row = {(record.package_type, record.capability, record.app_name): record for record in records}
    assert set(by_row) == {
        ("NonPackagedUsageHistory", "microphone", "Microsoft Edge"),
        ("NonPackagedUsageHistory", "webcam", "Camera"),
        ("PackagedUsageHistory", "webcam", "Camera"),
        ("PackagedUsageHistory", "microphone", "Sound Recorder"),
    }

    nonpackaged_mic = by_row[("NonPackagedUsageHistory", "microphone", "Microsoft Edge")]
    assert nonpackaged_mic.last_used_time_start == wintimestamp(_ticks(MIC_START))
    assert nonpackaged_mic.last_used_time_stop == wintimestamp(_ticks(MIC_STOP))
    assert nonpackaged_mic.duration == 1035
    assert nonpackaged_mic.username == "John"
    assert nonpackaged_mic.user_id == JOHN_SID
    assert nonpackaged_mic.binary_full_path == "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
    assert nonpackaged_mic.package_family_name is None
    assert nonpackaged_mic.service_name == "webthreatdefusersvc_110621"
    assert nonpackaged_mic.access_guid == "{6D809377-6AF0-444B-8957-A3773F02200E}"
    assert nonpackaged_mic.access_blocked == "0"
    assert nonpackaged_mic.label == "2"
    assert nonpackaged_mic.file_id == "0000f0bfca16305374262ad1919c258deba64fc25006"
    assert nonpackaged_mic.file_id_hash.sha1 == "f0bfca16305374262ad1919c258deba64fc25006"

    nonpackaged_cam = by_row[("NonPackagedUsageHistory", "webcam", "Camera")]
    assert nonpackaged_cam.binary_full_path == NONPACKAGED_CAMERA_PATH
    assert nonpackaged_cam.service_name is None

    packaged_cam = by_row[("PackagedUsageHistory", "webcam", "Camera")]
    assert packaged_cam.last_used_time_start == wintimestamp(_ticks(PACKAGED_START))
    assert packaged_cam.last_used_time_stop == wintimestamp(_ticks(PACKAGED_STOP))
    assert packaged_cam.duration == 5
    assert packaged_cam.username == "John"
    assert packaged_cam.package_family_name == "Microsoft.WindowsCamera_8wekyb3d8bbwe"
    assert packaged_cam.binary_full_path is None
    assert packaged_cam.file_id is None
    assert packaged_cam.service_name is None


def test_cam_history_unfinished_interval_keeps_open_identity(
    target_win_users: Target,
    fs_win: VirtualFilesystem,
    hive_hklm: VirtualHive,
    tmp_path: pathlib.Path,
) -> None:
    """A database row whose stop time is zero describes an interval that has not ended.

    It keeps its start time, claims no stop time, and reports no elapsed duration instead of one measured
    against the moment the test runs. Reading the same source twice yields the same evidence.
    """
    database = tmp_path / "CapabilityAccessManager.db"
    _build_capability_db(database)
    _map_capability_db(hive_hklm, fs_win, database)

    target_win_users.add_plugin(CamPlugin)
    first = _records_by_type(list(target_win_users.cam.history()), USAGE_RECORD)
    second = _records_by_type(list(target_win_users.cam.history()), USAGE_RECORD)

    open_record = next(record for record in first if record.last_used_time_stop is None)
    assert open_record.package_type == "NonPackagedUsageHistory"
    assert open_record.capability == "webcam"
    assert open_record.last_used_time_start == wintimestamp(_ticks(CAM_START))
    assert open_record.duration in (None, 0)
    assert open_record.username is None
    assert open_record.user_id is None
    assert open_record.binary_full_path == NONPACKAGED_CAMERA_PATH
    # an interval started in 2024 would measure many days against the present moment, so only an absent or zero
    # duration keeps the record an open interval
    assert open_record.duration in (None, 0)

    assert [_comparable(record) for record in first] == [_comparable(record) for record in second]


def test_cam_history_unknown_sid_keeps_its_source(
    target_win_users: Target,
    fs_win: VirtualFilesystem,
    hive_hklm: VirtualHive,
    tmp_path: pathlib.Path,
) -> None:
    """A row whose user SID resolves to no known user is still reported with its own times and application.

    Losing the user attribution must not drop the access interval or hand it to another user.
    """
    database = tmp_path / "CapabilityAccessManager.db"
    _build_capability_db(database)
    _map_capability_db(hive_hklm, fs_win, database)

    target_win_users.add_plugin(CamPlugin)
    records = [
        record
        for record in _records_by_type(list(target_win_users.cam.history()), USAGE_RECORD)
        if record.username is None
    ]
    assert len(records) == 1

    record = records[0]
    assert record.user_id is None
    assert record.last_used_time_start == wintimestamp(_ticks(CAM_START))
    assert record.capability == "webcam"
    assert record.access_blocked == "1"
    assert record.binary_full_path == NONPACKAGED_CAMERA_PATH


def test_cam_history_identity_relationship_source(
    target_win_users: Target,
    fs_win: VirtualFilesystem,
    hive_hklm: VirtualHive,
    tmp_path: pathlib.Path,
) -> None:
    """An identity relationship row keeps the observation time and application data of its own row."""
    database = tmp_path / "CapabilityAccessManager.db"
    _build_capability_db(database)
    _map_capability_db(hive_hklm, fs_win, database)

    target_win_users.add_plugin(CamPlugin)
    records = _records_by_type(list(target_win_users.cam.history()), IDENTITY_RECORD)
    assert len(records) == 1

    record = records[0]
    assert record.last_observed_time == wintimestamp(_ticks(OBSERVED_TIME))
    assert record.file_id == "0000f0bfca16305374262ad1919c258deba64fc25006"
    assert record.file_id_hash.sha1 == "f0bfca16305374262ad1919c258deba64fc25006"
    assert record.program_id == "00001495bc9d3674a3db3bbed7de63ca0f920000ffff"
    assert record.binary_full_path == "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"


@pytest.mark.xfail(reason="Known defect: the identity relationship record reuses the previous table name as source")
def test_cam_history_identity_relationship_source_label(
    target_win_users: Target,
    fs_win: VirtualFilesystem,
    hive_hklm: VirtualHive,
    tmp_path: pathlib.Path,
) -> None:
    """An identity relationship record names the table it was read from, so its source stays traceable."""
    database = tmp_path / "CapabilityAccessManager.db"
    _build_capability_db(database)
    _map_capability_db(hive_hklm, fs_win, database)

    target_win_users.add_plugin(CamPlugin)
    record = _records_by_type(list(target_win_users.cam.history()), IDENTITY_RECORD)[0]

    assert record.package_type == "NonPackagedIdentityRelationship"


def test_cam_history_prompt_source_is_not_an_access_interval(
    target_win_users: Target,
    fs_win: VirtualFilesystem,
    hive_hklm: VirtualHive,
    tmp_path: pathlib.Path,
) -> None:
    """A recorded permission prompt is reported under its own record type and is not an access interval."""
    database = tmp_path / "CapabilityAccessManager.db"
    _build_capability_db(database)
    _map_capability_db(hive_hklm, fs_win, database)

    target_win_users.add_plugin(CamPlugin)
    records = list(target_win_users.cam.history())

    prompts = _records_by_type(records, PROMPT_RECORD)
    assert len(prompts) == 1
    assert prompts[0].shown_time == wintimestamp(_ticks(PROMPT_TIME))
    assert prompts[0].capability == "webcam"
    assert prompts[0].file_id == "0000565c728f1a97551d85db2e788c69e0d8a18ea777"

    # the prompt is never counted as one of the usage intervals
    assert len(_records_by_type(records, USAGE_RECORD)) == 4
    assert all(hasattr(record, "last_used_time_start") for record in _records_by_type(records, USAGE_RECORD))


@pytest.mark.xfail(reason="Known defect: the prompt history record reuses the previous table name as source")
def test_cam_history_prompt_source_label(
    target_win_users: Target,
    fs_win: VirtualFilesystem,
    hive_hklm: VirtualHive,
    tmp_path: pathlib.Path,
) -> None:
    """A prompt history record names the table it was read from, so its source stays traceable."""
    database = tmp_path / "CapabilityAccessManager.db"
    _build_capability_db(database)
    _map_capability_db(hive_hklm, fs_win, database)

    target_win_users.add_plugin(CamPlugin)
    record = _records_by_type(list(target_win_users.cam.history()), PROMPT_RECORD)[0]

    assert record.package_type == "NonPackagedGlobalPromptHistory"


def test_cam_finished_and_open_intervals_share_one_duration_rule(
    target_win_users: Target,
    hive_hklm: VirtualHive,
    hive_hku: VirtualHive,
    fs_win: VirtualFilesystem,
    tmp_path: pathlib.Path,
) -> None:
    """Both record sources bound a duration only by a recorded stop time.

    Where a start and a stop exist, the duration is exactly the elapsed seconds between them, whichever source
    produced the record. Where the stop has not been recorded, the interval stays open and reports no elapsed
    duration (``None`` or zero) instead of one measured against the current time.
    """
    _attribute_user_hive(target_win_users, hive_hku)

    closed_app = _consent_app(hive_hku, "webcam", "Contoso.Used_8wekyb3d8bbwe")
    _set_interval(closed_app, hive_hku, REGISTRY_CAM_START, REGISTRY_CAM_STOP)
    open_app = _consent_app(hive_hku, "webcam", "Contoso.Live_8wekyb3d8bbwe")
    _set_interval(open_app, hive_hku, REGISTRY_OPEN_START, None)

    database = tmp_path / "CapabilityAccessManager.db"
    _build_capability_db(database)
    _map_capability_db(hive_hklm, fs_win, database)

    target_win_users.add_plugin(CamPlugin)
    registry_records = list(target_win_users.cam.registry())
    usage_records = _records_by_type(list(target_win_users.cam.history()), USAGE_RECORD)
    records = [*registry_records, *usage_records]

    finished = 0
    open_intervals = 0
    for record in records:
        start = getattr(record, "last_started", None) or getattr(record, "last_used_time_start", None)
        stop = getattr(record, "last_stopped", None) or getattr(record, "last_used_time_stop", None)

        if stop is None:
            open_intervals += 1
            assert record.duration in (None, 0)
        else:
            finished += 1
            assert record.duration == int((stop - start).total_seconds())

    # registry: one finished and one open camera interval; database: three finished and one open interval
    assert finished == 4
    assert open_intervals == 2
