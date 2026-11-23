from __future__ import annotations

import sqlite3
import uuid
from collections import defaultdict
from datetime import datetime as dt_datetime
from datetime import timedelta, timezone
from typing import TYPE_CHECKING

from flow.record import GroupedRecord
from flow.record.fieldtypes import datetime

from dissect.target.helpers import fsutil
from dissect.target.plugins.os.windows.notifications import (
    NOTIFICATIONS_DIR,
    NotificationsPlugin,
)
from tests._utils import absolute_path

if TYPE_CHECKING:
    import pathlib

    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target

USER_DIR = "Users\\John"


def test_notifications_appdb(target_win_users: Target, fs_win: VirtualFilesystem) -> None:
    test_file = absolute_path("_data/plugins/os/windows/notifications/appdb.dat.v3.gz")
    appdb_file = fsutil.join(USER_DIR, NOTIFICATIONS_DIR, "appdb.dat")
    fs_win.map_file(appdb_file, test_file, compression="gzip")
    target_win_users.add_plugin(NotificationsPlugin)

    records_by_type = defaultdict(list)
    for record in target_win_users.notifications.appdb():
        record_type = record._desc.name
        records_by_type[record_type].append(record)

    records_by_type_chunk = defaultdict(lambda: defaultdict(list))
    for record_type, records in records_by_type.items():
        if record_type != "windows/notification/appdb":
            for record in records:
                chunk_num = record.chunk_num
                records_by_type_chunk[record_type][chunk_num].append(record)

    assert len(records_by_type.get("windows/notification/appdb", [])) == 1
    assert len(records_by_type.get("windows/notification/appdb/push", [])) == 1
    assert len(records_by_type.get("windows/notification/appdb/badge", [])) == 2
    assert len(records_by_type.get("windows/notification/appdb/tile", [])) == 48
    assert len(records_by_type.get("windows/notification/appdb/toast", [])) == 35

    appdb_record = records_by_type["windows/notification/appdb"][0]
    assert appdb_record.timestamp == datetime("2016-06-02T10:00:34.019495+00:00")
    assert appdb_record.chunk_version == 3
    assert appdb_record.next_notification_id == 517

    push_record = records_by_type_chunk["windows/notification/appdb/push"][8][0]
    assert push_record.push_ts1 == datetime("2016-06-19T07:37:38+00:00")
    assert push_record.push_ts2 == datetime("2016-05-20T07:41:45.883432+00:00")
    assert push_record.push_uri == (
        "https://db5.notify.windows.com/?token=AwYAAAA%2bwMdZymXtvB9uG3YbJZX4U"
        "CXwsLBJA7it1REPu58SjiQ8%2bnxg%2bfk8vKU%2bQQPG5ZglOuCq%2fkArOGxBJr9z7G"
        "K%2bQFwyrTcaOyptsKNF2f%2fllCPmmGwXsFAFjS%2fkdC678PQ%3d"
    )

    badge_record = records_by_type_chunk["windows/notification/appdb/badge"][3][0]
    assert badge_record.badge_ts is None
    assert badge_record.badge_id == 0x7A
    assert badge_record.badge_data.startswith("<badge")

    badge_record = records_by_type_chunk["windows/notification/appdb/badge"][10][0]
    assert badge_record.badge_ts is None
    assert badge_record.badge_id == 0x18
    assert badge_record.badge_data.startswith("<badge")

    tiles = records_by_type_chunk["windows/notification/appdb/tile"][0]
    tile_ids = [0x01F9, 0x01AF, 0x01B6, 0x01BC, 0x01F3]
    for tile_no, tile in enumerate(tiles):
        assert tile.arrival_time.year == 2016
        assert tile.expiry_time.year == 2016
        assert tile.id == tile_ids[tile_no]
        assert tile.tile_type == 3
        assert tile.index == tile_no
        assert tile.name == ""
        assert tile.content.startswith("<?xml")

    toasts = records_by_type_chunk["windows/notification/appdb/toast"][3]
    toast_ids = [0x00BF, 0x00C1, 0x00B7, 0x00C0]
    toast_name1 = ["0", "0", "0", "1"]
    for toast_num, toast in enumerate(toasts):
        assert toast.id == toast_ids[toast_num]
        assert toast.name1 in toast_name1[toast_num]
        assert toast.name2 == "MailGroup"


def test_notifications_wpndatabase(target_win_users: Target, fs_win: VirtualFilesystem) -> None:
    test_file = absolute_path("_data/plugins/os/windows/notifications/wpndatabase.db")
    wpndatabase_file = fsutil.join(USER_DIR, NOTIFICATIONS_DIR, "wpndatabase.db")
    fs_win.map_file(wpndatabase_file, test_file)

    target_win_users.add_plugin(NotificationsPlugin)

    records = list(target_win_users.notifications.wpndatabase())

    assert len(records) == 3


def _to_windows_timestamp(value: dt_datetime) -> int:
    """Convert a datetime to a Windows timestamp (100ns intervals since 1601-01-01)."""
    epoch = dt_datetime(1601, 1, 1, tzinfo=timezone.utc)
    return int((value - epoch).total_seconds() * 10**7)


def _create_wpndatabase(path: pathlib.Path) -> None:
    """Create a minimal wpndatabase.db with edge cases for notification-handler association."""
    now = dt_datetime.now(tz=timezone.utc)

    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TABLE NotificationHandler ("
            "[RecordId] INTEGER, [PrimaryId] TEXT, [WNSId] TEXT, [HandlerType] TEXT, "
            "[WNFEventName] INTEGER, [SystemDataPropertySet] BLOB, [CreatedTime] TEXT, [ModifiedTime] TEXT)"
        )
        db.execute(
            "CREATE TABLE Notification ("
            "[Id] INTEGER, [HandlerId] INTEGER, [Order] INTEGER, [Type] TEXT, [Payload] BLOB, [PayloadType] TEXT, "
            "[ArrivalTime] INTEGER, [ExpiryTime] INTEGER, [Tag] TEXT, [Group] TEXT, [ActivityId] BLOB, "
            "[BootId] INTEGER, [ExpiresOnReboot] TEXT)"
        )

        # Two handlers share the same PrimaryId (duplicate application identifier).
        handlers = [
            (1, "App.Duplicate", "wns-1", "toast", 1, b"", "2023-01-01 00:00:00", "2023-01-01 00:00:00"),
            (2, "App.Duplicate", "wns-2", "toast", 2, b"", "2023-01-02 00:00:00", "2023-01-02 00:00:00"),
            (3, "App.Unique", "wns-3", "toast", 3, b"", "2023-01-03 00:00:00", "2023-01-03 00:00:00"),
        ]
        db.executemany("INSERT INTO NotificationHandler VALUES (?, ?, ?, ?, ?, ?, ?, ?)", handlers)

        notifications = [
            # Delivered notification for handler 2 (duplicate PrimaryId with handler 1).
            (
                1,
                2,
                1,
                "toast",
                b"<toast/>",
                "xml",
                _to_windows_timestamp(now),
                _to_windows_timestamp(now + timedelta(days=1)),
                "tag",
                "group",
                uuid.uuid4().bytes,
                1,
                "FALSE",
            ),
            # Expired notification for handler 1.
            (
                2,
                1,
                2,
                "toast",
                b"<toast/>",
                "xml",
                _to_windows_timestamp(now - timedelta(days=2)),
                _to_windows_timestamp(now - timedelta(days=1)),
                "tag",
                "group",
                uuid.uuid4().bytes,
                1,
                "FALSE",
            ),
            # Notification referencing a handler that is missing from the database.
            (
                3,
                42,
                3,
                "toast",
                b"<toast/>",
                "xml",
                _to_windows_timestamp(now),
                _to_windows_timestamp(now + timedelta(days=1)),
                "tag",
                "group",
                uuid.uuid4().bytes,
                1,
                "FALSE",
            ),
        ]
        db.executemany("INSERT INTO Notification VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", notifications)


def test_notifications_wpndatabase_traceability(
    target_win_users: Target, fs_win: VirtualFilesystem, tmp_path: pathlib.Path
) -> None:
    """Notifications must stay traceable to their handler, even with duplicate app ids or missing handlers."""
    test_file = tmp_path / "wpndatabase.db"
    _create_wpndatabase(test_file)

    wpndatabase_file = fsutil.join(USER_DIR, NOTIFICATIONS_DIR, "wpndatabase.db")
    fs_win.map_file(wpndatabase_file, str(test_file))

    target_win_users.add_plugin(NotificationsPlugin)

    records = list(target_win_users.notifications.wpndatabase())
    assert len(records) == 3

    by_notification_id = {}
    for record in records:
        notification = record
        if isinstance(record, GroupedRecord):
            notification = record.get_record_by_type("windows/notification/wpndatabase")
        by_notification_id[notification.id] = record

    # Notification 1: associated with handler 2, not handler 1, despite both
    # handlers sharing the same PrimaryId. The association is by HandlerId.
    record = by_notification_id[1]
    assert isinstance(record, GroupedRecord)
    handler = record.get_record_by_type("windows/notification/wpndatabase/handler")
    assert handler.id == 2
    assert record.handler_id == 2
    assert record.handler_primary_id == "App.Duplicate"
    assert record.handler_match == "handler_id"
    assert record.status == "delivered"

    # Notification 2: expired, so the delivery conclusion differs from its
    # mere presence in the database.
    record = by_notification_id[2]
    assert isinstance(record, GroupedRecord)
    assert record.handler_primary_id == "App.Duplicate"
    assert record.handler_match == "handler_id"
    assert record.status == "expired"

    # Notification 3: the handler is missing, so it is yielded on its own but
    # remains independently traceable.
    record = by_notification_id[3]
    assert not isinstance(record, GroupedRecord)
    assert record._desc.name == "windows/notification/wpndatabase"
    assert record.handler_id == 42
    assert record.handler_primary_id is None
    assert record.handler_match is None
    assert record.status == "no_handler"
