from __future__ import annotations

import datetime
from io import BytesIO
from typing import TYPE_CHECKING

from dissect.util.ts import wintimestamp

from dissect.target.plugins.os.windows.wer import WindowsErrorReportingPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target

WER_ROOT = "ProgramData/Microsoft/Windows/WER"
WER_REPORT_FILENAME = "AppCrash_same_app.exe_1a2b3c.wer"
WER_METADATA_FILENAME = f"{WER_REPORT_FILENAME}.tmp.WERInternalMetadata.xml"
SAME_APP_NAME = "same_app.exe"

ARCHIVE_REPORT_DIR = "ReportArchive/AppCrash_same_app.exe_1"
QUEUE_REPORT_DIR = "ReportQueue/AppCrash_same_app.exe_1"
ARCHIVE_EVENT_TIME = 133093548000000000
QUEUE_EVENT_TIME = 133093559000000000


def test_wer_plugin(target_win: Target, fs_win: VirtualFilesystem) -> None:
    wer_dir = absolute_path("_data/plugins/os/windows/wer")
    fs_win.map_dir("ProgramData/Microsoft/Windows/WER/ReportQueue/test", wer_dir)
    target_win.add_plugin(WindowsErrorReportingPlugin)
    tests = [
        "os_version_information_lcid",
        "response_type",
        "sig",
        "dynamic_sig",
        "dynamic_signatures_parameter1",
        "ui_x5b_1_x5d",
        "sp_xc3a9_cial_charact_xc3a9_r",
        "xd0bd_xd0b5_xd0b2_xd0b8_xd0b4_xd0b8_xd0bc_xd18b_xd0b9",
        "x5f_start_with_an_",
        "x33__start_with_a_3",
    ]

    records = list(target_win.wer())
    assert len(records) == 2

    wer_record_map = {r.wer_file_path.name: r for r in records}
    assert "wer_test.wer" in wer_record_map
    assert "wer_test_no_bom.wer" in wer_record_map

    record = wer_record_map["wer_test.wer"]
    for test in tests:
        record_field = getattr(record, test, None)
        assert record_field == f"test_{test}"

    assert record.ts == datetime.datetime(2022, 10, 4, 11, 0, 0, 0, tzinfo=datetime.timezone.utc)

    record = wer_record_map["wer_test_no_bom.wer"]
    assert record.ts == datetime.datetime(2021, 11, 22, 15, 39, 49, 20733, tzinfo=datetime.timezone.utc)
    assert record.os_version == "6.1.7601.2.1.0.256.48"
    assert record.app_name == "Microsoft Malware Protection Command Line Utility"


def test_wer_plugin_key_in_report_and_metadata(target_win: Target, fs_win: VirtualFilesystem) -> None:
    """A key that is in both the report and its metadata is a single field, with the value of the report."""
    report_dir = "ProgramData/Microsoft/Windows/WER/ReportQueue/test"
    fs_win.map_file_fh(
        f"{report_dir}/report.wer",
        BytesIO("EventType=test_event_type\r\nOSVersionInformationLCID=from_report\r\n".encode("utf-16")),
    )
    fs_win.map_file_fh(
        f"{report_dir}/report.tmp.WERInternalMetadata.xml",
        BytesIO(
            (
                '<?xml version="1.0" encoding="UTF-16"?>\n'
                "<WERReportMetadata><OSVersionInformation><LCID>from_metadata</LCID></OSVersionInformation>"
                "</WERReportMetadata>"
            ).encode("utf-16")
        ),
    )
    target_win.add_plugin(WindowsErrorReportingPlugin)

    records = list(target_win.wer())
    assert len(records) == 1

    record = records[0]
    field_names = [name for _, name in record._desc.get_field_tuples()]
    assert field_names.count("os_version_information_lcid") == 1
    assert record.os_version_information_lcid == "from_report"
    assert record.event_type == "test_event_type"


def _wer_report(
    report_identifier: str,
    app_session_guid: str | None = None,
    event_time: int = ARCHIVE_EVENT_TIME,
    app_name: str = SAME_APP_NAME,
) -> bytes:
    """Build the contents of a ``.wer`` report of an application crash."""
    lines = [
        "Version=1",
        "EventType=APPCRASH",
        f"EventTime={event_time}",
        f"ReportIdentifier={report_identifier}",
        f"AppName={app_name}",
        f"AppPath=C:\\Program Files\\Vendor\\{app_name}",
    ]
    if app_session_guid is not None:
        lines.append(f"AppSessionGuid={app_session_guid}")
    return ("\r\n".join(lines) + "\r\n").encode("utf-16")


def _wer_metadata(
    guid: str,
    pid: str | None = None,
    report_identifier: str | None = None,
) -> bytes:
    """Build the contents of the ``WERInternalMetadata.xml`` file belonging to a single report."""
    report_information = f"<Guid>{guid}</Guid>"
    if report_identifier is not None:
        report_information += f"<ReportIdentifier>{report_identifier}</ReportIdentifier>"
    process_information = f"<ProcessInformation><Pid>{pid}</Pid></ProcessInformation>" if pid else ""

    xml = (
        '<?xml version="1.0" encoding="UTF-16"?>\n'
        "<WERReportMetadata>"
        f"<ReportInformation>{report_information}</ReportInformation>"
        f"{process_information}"
        "</WERReportMetadata>"
    )
    return xml.encode("utf-16")


def _plant_wer_report(
    fs_win: VirtualFilesystem,
    directory: str,
    report_identifier: str,
    app_session_guid: str | None = None,
    event_time: int = ARCHIVE_EVENT_TIME,
    metadata: tuple[str, str | None, str | None] | None = None,
) -> str:
    """Plant a report in ``directory`` and, when given, a metadata file next to it.

    The ``metadata`` tuple holds the GUID, PID and report identifier of the metadata file.

    Returns:
        The normalized path of the planted report, for matching it against a record.
    """
    fs_win.map_file_fh(
        f"{WER_ROOT}/{directory}/{WER_REPORT_FILENAME}",
        BytesIO(_wer_report(report_identifier, app_session_guid, event_time)),
    )
    if metadata is not None:
        fs_win.map_file_fh(
            f"{WER_ROOT}/{directory}/{WER_METADATA_FILENAME}",
            BytesIO(_wer_metadata(*metadata)),
        )
    return f"sysvol/{WER_ROOT}/{directory}/{WER_REPORT_FILENAME}".lower()


def _normalize(path: object) -> str:
    """Normalize a record path so it can be compared with paths planted on the test filesystem."""
    return str(path).replace("\\", "/").lower()


def _field_names(record: object) -> list[str]:
    return [name for _, name in record._desc.get_field_tuples()]


def _values(record: object) -> set[str]:
    return {str(value) for value in record._asdict().values()}


def test_wer_same_named_app_reports_stay_separate_by_source(target_win: Target, fs_win: VirtualFilesystem) -> None:
    """Reports of an identically named application in different directories are separate events.

    Every record must take its identity (report identifier, session information and timestamp) from the report
    at its own path; a same-named event in another directory must not contribute any of its fields.
    """
    archive_report = _plant_wer_report(
        fs_win,
        ARCHIVE_REPORT_DIR,
        report_identifier="archive-report",
        app_session_guid="archive-session",
        event_time=ARCHIVE_EVENT_TIME,
    )
    queue_report = _plant_wer_report(
        fs_win,
        QUEUE_REPORT_DIR,
        report_identifier="queue-report",
        app_session_guid="queue-session",
        event_time=QUEUE_EVENT_TIME,
    )
    target_win.add_plugin(WindowsErrorReportingPlugin)

    records = list(target_win.wer())
    assert len(records) == 2

    by_source = {_normalize(record.wer_file_path): record for record in records}
    assert set(by_source) == {archive_report, queue_report}

    expected = {
        archive_report: ("archive-report", "archive-session", ARCHIVE_EVENT_TIME),
        queue_report: ("queue-report", "queue-session", QUEUE_EVENT_TIME),
    }
    for source, record in by_source.items():
        report_identifier, session_guid, event_time = expected[source]

        assert record.app_name == SAME_APP_NAME
        assert record.report_identifier == report_identifier
        assert record.app_session_guid == session_guid
        assert record.ts == wintimestamp(event_time)
        assert record.metadata_file_path is None

        # the report at this source holds exactly this identity
        report_text = target_win.fs.path(str(record.wer_file_path)).read_text("utf-16")
        assert f"ReportIdentifier={report_identifier}" in report_text
        assert f"AppSessionGuid={session_guid}" in report_text

        # the identity of the other event has not leaked into this record
        for other_source, (other_identifier, other_session, _) in expected.items():
            if other_source == source:
                continue
            assert other_identifier not in _values(record)
            assert other_session not in _values(record)


def test_wer_duplicate_report_identifier_does_not_collapse_sources(
    target_win: Target, fs_win: VirtualFilesystem
) -> None:
    """A shared report identifier does not merge two events that have different sources.

    The report identifier alone must not be used as the merge key: two reports in different directories stay two
    events, each with the session information of the report at its own path.
    """
    archive_report = _plant_wer_report(
        fs_win,
        ARCHIVE_REPORT_DIR,
        report_identifier="duplicate-identifier",
        app_session_guid="archive-session",
        event_time=ARCHIVE_EVENT_TIME,
    )
    queue_report = _plant_wer_report(
        fs_win,
        QUEUE_REPORT_DIR,
        report_identifier="duplicate-identifier",
        app_session_guid="queue-session",
        event_time=QUEUE_EVENT_TIME,
    )
    target_win.add_plugin(WindowsErrorReportingPlugin)

    records = list(target_win.wer())
    assert len(records) == 2

    by_source = {_normalize(record.wer_file_path): record for record in records}
    assert set(by_source) == {archive_report, queue_report}
    assert {record.report_identifier for record in records} == {"duplicate-identifier"}

    sessions = {}
    for source, record in by_source.items():
        # the session information of each record is the one in the report at its own source
        report_text = target_win.fs.path(str(record.wer_file_path)).read_text("utf-16")
        assert f"AppSessionGuid={record.app_session_guid}" in report_text
        sessions[source] = record.app_session_guid

    assert sessions == {archive_report: "archive-session", queue_report: "queue-session"}


def test_wer_metadata_stays_with_the_report_of_its_own_directory(target_win: Target, fs_win: VirtualFilesystem) -> None:
    """Attached metadata of one report must not enter the event of a same-named report elsewhere."""
    archive_report = _plant_wer_report(
        fs_win,
        ARCHIVE_REPORT_DIR,
        report_identifier="archive-report",
        app_session_guid="archive-session",
        metadata=("archive-meta-guid", "archive-meta-pid", None),
    )
    queue_report = _plant_wer_report(
        fs_win,
        QUEUE_REPORT_DIR,
        report_identifier="queue-report",
        app_session_guid="queue-session",
        event_time=QUEUE_EVENT_TIME,
    )
    target_win.add_plugin(WindowsErrorReportingPlugin)

    records = list(target_win.wer())
    assert len(records) == 2
    by_source = {_normalize(record.wer_file_path): record for record in records}

    archive_record = by_source[archive_report]
    assert archive_record.metadata_file_path is not None
    assert _normalize(archive_record.metadata_file_path) == _normalize(
        target_win.fs.path(f"sysvol/{WER_ROOT}/{ARCHIVE_REPORT_DIR}/{WER_METADATA_FILENAME}")
    )
    assert archive_record.report_information_guid == "archive-meta-guid"
    assert archive_record.process_information_pid == "archive-meta-pid"

    queue_record = by_source[queue_report]
    # the metadata-less report keeps no metadata path and no metadata-derived fields
    assert queue_record.metadata_file_path is None
    assert "report_information_guid" not in _field_names(queue_record)
    assert "process_information_pid" not in _field_names(queue_record)
    assert "archive-meta-guid" not in _values(queue_record)
    assert "archive-meta-pid" not in _values(queue_record)


def test_wer_metadata_without_report_enters_no_report_event(target_win: Target, fs_win: VirtualFilesystem) -> None:
    """Stale metadata left behind in a directory without a report does not enter any report event."""
    archive_report = _plant_wer_report(
        fs_win,
        ARCHIVE_REPORT_DIR,
        report_identifier="archive-report",
        app_session_guid="archive-session",
    )
    queue_report = _plant_wer_report(
        fs_win,
        QUEUE_REPORT_DIR,
        report_identifier="queue-report",
        app_session_guid="queue-session",
        event_time=QUEUE_EVENT_TIME,
    )
    # stale metadata of an older report of the same application whose report is gone
    fs_win.map_file_fh(
        f"{WER_ROOT}/ReportArchive/AppCrash_same_app.exe_0/{WER_METADATA_FILENAME}",
        BytesIO(_wer_metadata("stale-meta-guid", "stale-meta-pid", "stale-report")),
    )
    target_win.add_plugin(WindowsErrorReportingPlugin)

    records = list(target_win.wer())
    report_records = {
        _normalize(record.wer_file_path): record for record in records if record.wer_file_path is not None
    }
    assert set(report_records) == {archive_report, queue_report}

    for record in report_records.values():
        # nothing of the stale metadata enters a report event
        assert "stale-meta-guid" not in _values(record)
        assert "stale-meta-pid" not in _values(record)
        assert "stale-report" not in _values(record)
        assert record.metadata_file_path is None

    # the stale metadata itself stays traceable through its own record, tied to its own path
    stale_records = [record for record in records if record.wer_file_path is None]
    assert len(stale_records) == 1
    stale_record = stale_records[0]
    assert _normalize(stale_record.metadata_file_path) == _normalize(
        target_win.fs.path(f"sysvol/{WER_ROOT}/ReportArchive/AppCrash_same_app.exe_0/{WER_METADATA_FILENAME}")
    )
    assert target_win.fs.path(str(stale_record.metadata_file_path)).is_file()
    assert stale_record.report_information_guid == "stale-meta-guid"
    assert stale_record.process_information_pid == "stale-meta-pid"


def test_wer_stale_metadata_does_not_override_report_identity(target_win: Target, fs_win: VirtualFilesystem) -> None:
    """Conflicting metadata is attached, but the identity of the report itself takes precedence."""
    archive_report = _plant_wer_report(
        fs_win,
        ARCHIVE_REPORT_DIR,
        report_identifier="archive-report",
        app_session_guid="archive-session",
        metadata=("archive-meta-guid", "archive-meta-pid", "stale-report"),
    )
    target_win.add_plugin(WindowsErrorReportingPlugin)

    records = list(target_win.wer())
    assert len(records) == 1

    record = records[0]
    assert _normalize(record.wer_file_path) == archive_report
    assert record.metadata_file_path is not None
    # identity fields are the ones of the report, not the stale identifier of the metadata
    assert record.report_identifier == "archive-report"
    assert record.app_session_guid == "archive-session"
    # the metadata value stays under its own field name, traceable to the metadata file
    assert record.report_information_report_identifier == "stale-report"

    metadata_text = target_win.fs.path(str(record.metadata_file_path)).read_text("utf-16")
    assert "stale-report" in metadata_text
    assert "archive-report" not in metadata_text


def test_wer_incomplete_metadata_leaves_fields_absent(target_win: Target, fs_win: VirtualFilesystem) -> None:
    """Metadata missing a field leaves that field absent instead of borrowing it from another event."""
    archive_report = _plant_wer_report(
        fs_win,
        ARCHIVE_REPORT_DIR,
        report_identifier="archive-report",
        app_session_guid="archive-session",
        metadata=("archive-meta-guid", "archive-meta-pid", None),
    )
    queue_report = _plant_wer_report(
        fs_win,
        QUEUE_REPORT_DIR,
        report_identifier="queue-report",
        app_session_guid="queue-session",
        event_time=QUEUE_EVENT_TIME,
        # metadata of this report carries no process information at all
        metadata=("queue-meta-guid", None, None),
    )
    target_win.add_plugin(WindowsErrorReportingPlugin)

    records = list(target_win.wer())
    assert len(records) == 2
    by_source = {_normalize(record.wer_file_path): record for record in records}

    queue_record = by_source[queue_report]
    assert queue_record.metadata_file_path is not None
    assert queue_record.report_information_guid == "queue-meta-guid"
    # the missing field stays absent; it is not completed with the value of the same-named event
    assert "process_information_pid" not in _field_names(queue_record)
    assert "archive-meta-pid" not in _values(queue_record)

    archive_record = by_source[archive_report]
    assert archive_record.process_information_pid == "archive-meta-pid"


def test_wer_session_information_is_not_borrowed_from_another_event(
    target_win: Target, fs_win: VirtualFilesystem
) -> None:
    """A report without session information keeps that information absent instead of taking it from a sibling."""
    with_session = _plant_wer_report(
        fs_win,
        ARCHIVE_REPORT_DIR,
        report_identifier="with-session",
        app_session_guid="distinct-session-guid",
    )
    without_session = _plant_wer_report(
        fs_win,
        QUEUE_REPORT_DIR,
        report_identifier="without-session",
        event_time=QUEUE_EVENT_TIME,
    )
    target_win.add_plugin(WindowsErrorReportingPlugin)

    records = list(target_win.wer())
    assert len(records) == 2
    by_source = {_normalize(record.wer_file_path): record for record in records}

    session_record = by_source[with_session]
    assert session_record.app_session_guid == "distinct-session-guid"
    session_report_text = target_win.fs.path(str(session_record.wer_file_path)).read_text("utf-16")
    assert "AppSessionGuid=distinct-session-guid" in session_report_text

    no_session_record = by_source[without_session]
    # the report has no session information at all, so the field is absent and no other value is substituted
    assert "app_session_guid" not in _field_names(no_session_record)
    no_session_report_text = target_win.fs.path(str(no_session_record.wer_file_path)).read_text("utf-16")
    assert "AppSessionGuid" not in no_session_report_text
    assert no_session_record.report_identifier == "without-session"
    assert "distinct-session-guid" not in _values(no_session_record)


def test_wer_report_metadata_and_session_information_are_traceable(
    target_win: Target, fs_win: VirtualFilesystem
) -> None:
    """Report path, metadata path and obtainable session information of every event are individually traceable."""
    archive_report = _plant_wer_report(
        fs_win,
        ARCHIVE_REPORT_DIR,
        report_identifier="archive-report",
        app_session_guid="archive-session",
        metadata=("archive-meta-guid", "archive-meta-pid", None),
    )
    queue_report = _plant_wer_report(
        fs_win,
        "ReportQueue/AppCrash_same_app.exe_2",
        report_identifier="queue-report",
        app_session_guid="queue-session",
        event_time=QUEUE_EVENT_TIME,
        metadata=("queue-meta-guid", "queue-meta-pid", None),
    )
    target_win.add_plugin(WindowsErrorReportingPlugin)

    records = list(target_win.wer())
    assert len(records) == 2

    expected = {
        archive_report: ("archive-session", "archive-meta-guid", "archive-meta-pid"),
        queue_report: ("queue-session", "queue-meta-guid", "queue-meta-pid"),
    }
    for record in records:
        source = _normalize(record.wer_file_path)
        session_guid, metadata_guid, metadata_pid = expected[source]

        # the report path resolves to the report holding this event's session information
        report_path = target_win.fs.path(str(record.wer_file_path))
        assert report_path.is_file()
        report_text = report_path.read_text("utf-16")
        assert f"AppSessionGuid={session_guid}" in report_text
        assert record.app_session_guid == session_guid

        # the metadata path resolves to the metadata holding this event's metadata
        metadata_path = target_win.fs.path(str(record.metadata_file_path))
        assert metadata_path.is_file()
        metadata_text = metadata_path.read_text("utf-16")
        assert metadata_guid in metadata_text
        assert metadata_pid in metadata_text
        assert record.report_information_guid == metadata_guid
        assert record.process_information_pid == metadata_pid

        # report and metadata belong to the same report directory
        assert _normalize(report_path.parent) == _normalize(metadata_path.parent)
        assert _normalize(metadata_path) == _normalize(report_path.parent.joinpath(WER_METADATA_FILENAME))

        # the metadata of the other event enters neither this metadata nor this record
        for other_source, (_, other_guid, other_pid) in expected.items():
            if other_source == source:
                continue
            assert other_guid not in metadata_text
            assert other_pid not in metadata_text
            assert other_guid not in _values(record)
            assert other_pid not in _values(record)
