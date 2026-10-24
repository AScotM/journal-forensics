
import argparse
import collections
import csv
import datetime as dt
import json
import math
import os
import re
import statistics
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

UTC = dt.timezone.utc

PRIORITIES = {
    "emerg": 0,
    "alert": 1,
    "crit": 2,
    "err": 3,
    "warning": 4,
    "notice": 5,
    "info": 6,
    "debug": 7,
}

PRIORITY_NAMES = {
    value: key for key, value in PRIORITIES.items()
}

PATTERNS = {
    "service_failure": re.compile(
        r"failed|failure|main process exited|start request repeated",
        re.I,
    ),
    "authentication": re.compile(
        r"authentication failure|failed password|invalid user|pam_unix",
        re.I,
    ),
    "permission": re.compile(
        r"permission denied|operation not permitted|access denied",
        re.I,
    ),
    "resource_exhaustion": re.compile(
        r"out of memory|oom.kill|no space left|too many open files",
        re.I,
    ),
    "storage": re.compile(
        r"i/o error|filesystem error|read-only file system|buffer i/o",
        re.I,
    ),
    "network": re.compile(
        r"network unreachable|connection refused|timed out|dns failure",
        re.I,
    ),
    "kernel": re.compile(
        r"kernel panic|general protection fault|segfault|call trace",
        re.I,
    ),
    "security": re.compile(
        r"avc:.*denied|selinux.*denied|audit.*denied",
        re.I,
    ),
}

SENSITIVE = re.compile(
    r"(?i)\b(password|passwd|token|secret|api[_-]?key|authorization)"
    r"(\s*[:=]\s*|\s+)([^\s,;]+)"
)

@dataclass
class Event:
    timestamp: dt.datetime
    priority: int
    unit: str
    identifier: str
    pid: str
    boot_id: str
    message: str
    categories: list = field(default_factory=list)

    def to_dict(self):
        return {
            "timestamp": self.timestamp.isoformat(),
            "priority": self.priority,
            "priority_name": PRIORITY_NAMES.get(
                self.priority, "unknown"
            ),
            "unit": self.unit,
            "identifier": self.identifier,
            "pid": self.pid,
            "boot_id": self.boot_id,
            "message": self.message,
            "categories": self.categories,
        }


def normalize_message(value):
    if isinstance(value, str):
        return value

    if isinstance(value, list):
        try:
            return bytes(value).decode("utf-8", "replace")
        except (ValueError, TypeError):
            return str(value)

    if value is None:
        return ""

    return str(value)


def redact(message):
    return SENSITIVE.sub(
        lambda match: match.group(1) + "=REDACTED",
        message,
    )


def parse_timestamp(value):
    try:
        microseconds = int(value)
        return dt.datetime.fromtimestamp(
            microseconds / 1_000_000,
            tz=UTC,
        )
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def parse_priority(value):
    try:
        number = int(value)
        return number if 0 <= number <= 7 else 6
    except (ValueError, TypeError):
        return 6


def classify(message):
    return [
        category
        for category, pattern in PATTERNS.items()
        if pattern.search(message)
    ]


def parse_event(record, redact_sensitive=True):
    timestamp = parse_timestamp(
        record.get("__REALTIME_TIMESTAMP")
    )

    if timestamp is None:
        return None

    message = normalize_message(record.get("MESSAGE"))

    if redact_sensitive:
        message = redact(message)

    return Event(
        timestamp=timestamp,
        priority=parse_priority(record.get("PRIORITY", 6)),
        unit=str(
            record.get("_SYSTEMD_UNIT")
            or record.get("UNIT")
            or record.get("OBJECT_SYSTEMD_UNIT")
            or "unknown"
        ),
        identifier=str(
            record.get("SYSLOG_IDENTIFIER")
            or record.get("_COMM")
            or "unknown"
        ),
        pid=str(record.get("_PID") or ""),
        boot_id=str(record.get("_BOOT_ID") or "unknown"),
        message=message,
        categories=classify(message),
    )


def journal_command(args):
    command = [
        "journalctl",
        "--no-pager",
        "--output=json",
        "--quiet",
    ]

    if args.since:
        command.extend(["--since", args.since])

    if args.until:
        command.extend(["--until", args.until])

    if args.unit:
        for unit in args.unit:
            command.extend(["--unit", unit])

    if args.boot is not None:
        command.extend(["--boot", args.boot])

    if args.priority is not None:
        command.extend([
            "--priority",
            str(args.priority),
        ])

    if args.lines:
        command.extend(["--lines", str(args.lines)])

    if args.directory:
        command.extend(["--directory", args.directory])

    if args.user:
        command.append("--user")

    return command


def load_journal(args):
    command = journal_command(args)

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
        )
    except FileNotFoundError:
        raise RuntimeError("journalctl is not installed")

    events = []
    malformed = 0

    try:
        for line in process.stdout:
            if not line.strip():
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                malformed += 1
                continue

            if not isinstance(record, dict):
                malformed += 1
                continue

            event = parse_event(
                record,
                redact_sensitive=not args.no_redact,
            )

            if event is None:
                malformed += 1
                continue

            if args.search and not re.search(
                args.search,
                event.message,
                re.I,
            ):
                continue

            if args.category and not (
                set(args.category) & set(event.categories)
            ):
                continue

            events.append(event)

    except KeyboardInterrupt:
        process.terminate()
        process.wait()
        raise

    stderr = process.stderr.read()
    return_code = process.wait()

    if return_code:
        raise RuntimeError(
            stderr.strip() or
            f"journalctl exited with status {return_code}"
        )

    events.sort(key=lambda event: event.timestamp)

    return events, malformed


def normalize_signature(message):
    message = re.sub(
        r"\b[0-9a-f]{8,}\b",
        "<hex>",
        message,
        flags=re.I,
    )
    message = re.sub(
        r"\b\d+\b",
        "<number>",
        message,
    )
    message = re.sub(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "<ip>",
        message,
    )
    message = re.sub(
        r"\s+",
        " ",
        message,
    )
    return message.strip().lower()[:300]


def event_buckets(events, interval):
    buckets = collections.Counter()

    for event in events:
        timestamp = int(event.timestamp.timestamp())
        bucket = timestamp - timestamp % interval
        buckets[bucket] += 1

    return buckets


def detect_bursts(events, interval, threshold):
    buckets = event_buckets(events, interval)

    results = []

    for timestamp, count in sorted(buckets.items()):
        if count >= threshold:
            results.append({
                "start": dt.datetime.fromtimestamp(
                    timestamp,
                    tz=UTC,
                ).isoformat(),
                "events": count,
                "interval_seconds": interval,
            })

    return results


def detect_anomalies(events, interval, sigma):
    buckets = event_buckets(events, interval)

    if not buckets:
        return []

    first = min(buckets)
    last = max(buckets)

    counts = [
        buckets.get(timestamp, 0)
        for timestamp in range(
            first,
            last + interval,
            interval,
        )
    ]

    if len(counts) < 3:
        return []

    mean = statistics.mean(counts)
    deviation = statistics.pstdev(counts)

    if deviation == 0:
        return []

    results = []

    for index, count in enumerate(counts):
        score = (count - mean) / deviation

        if score >= sigma:
            timestamp = first + index * interval

            results.append({
                "start": dt.datetime.fromtimestamp(
                    timestamp,
                    tz=UTC,
                ).isoformat(),
                "events": count,
                "z_score": round(score, 3),
                "baseline_mean": round(mean, 3),
            })

    return results


def repeated_messages(events, minimum, limit):
    counter = collections.Counter()
    examples = {}

    for event in events:
        signature = normalize_signature(event.message)

        if not signature:
            continue

        key = (event.unit, signature)
        counter[key] += 1
        examples.setdefault(key, event.message)

    results = []

    for key, count in counter.most_common():
        if count < minimum:
            continue

        unit, signature = key

        results.append({
            "unit": unit,
            "count": count,
            "signature": signature,
            "example": examples[key],
        })

        if len(results) >= limit:
            break

    return results


def analyze_boots(events):
    groups = collections.defaultdict(list)

    for event in events:
        groups[event.boot_id].append(event)

    results = []

    for boot_id, group in sorted(
        groups.items(),
        key=lambda item: item[1][0].timestamp,
    ):
        results.append({
            "boot_id": boot_id,
            "first_event": group[0].timestamp.isoformat(),
            "last_event": group[-1].timestamp.isoformat(),
            "events": len(group),
            "errors": sum(
                event.priority <= 3
                for event in group
            ),
        })

    return results


def analyze_units(events, limit):
    groups = collections.defaultdict(list)

    for event in events:
        groups[event.unit].append(event)

    results = []

    for unit, group in groups.items():
        priorities = collections.Counter(
            event.priority for event in group
        )

        categories = collections.Counter(
            category
            for event in group
            for category in event.categories
        )

        results.append({
            "unit": unit,
            "events": len(group),
            "errors": sum(
                count
                for priority, count in priorities.items()
                if priority <= 3
            ),
            "warnings": priorities.get(4, 0),
            "categories": dict(categories),
            "first_seen": group[0].timestamp.isoformat(),
            "last_seen": group[-1].timestamp.isoformat(),
        })

    results.sort(
        key=lambda item: (
            -item["errors"],
            -item["warnings"],
            -item["events"],
        )
    )

    return results[:limit]


def calculate_health(events):
    if not events:
        return {
            "score": None,
            "level": "unknown",
            "reason": "No events available",
        }

    errors = sum(
        event.priority <= 3
        for event in events
    )

    warnings = sum(
        event.priority == 4
        for event in events
    )

    failures = sum(
        "service_failure" in event.categories
        for event in events
    )

    resource_events = sum(
        "resource_exhaustion" in event.categories
        for event in events
    )

    total = len(events)

    error_ratio = errors / total
    warning_ratio = warnings / total

    penalty = (
        error_ratio * 55
        + warning_ratio * 15
        + min(failures, 20) * 1.2
        + min(resource_events, 10) * 2
    )

    score = max(0, round(100 - penalty, 2))

    if score >= 90:
        level = "low observed journal severity"
    elif score >= 70:
        level = "moderate observed journal severity"
    elif score >= 45:
        level = "elevated observed journal severity"
    else:
        level = "high observed journal severity"

    return {
        "score": score,
        "level": level,
        "reason": "Heuristic based on journal event distribution",
    }


def build_report(events, malformed, args):
    priorities = collections.Counter(
        event.priority for event in events
    )

    categories = collections.Counter(
        category
        for event in events
        for category in event.categories
    )

    identifiers = collections.Counter(
        event.identifier for event in events
    )

    report = {
        "tool": "journal-forensics",
        "generated_at": dt.datetime.now(UTC).isoformat(),
        "hostname": os.uname().nodename,
        "parameters": {
            "since": args.since,
            "until": args.until,
            "units": args.unit,
            "boot": args.boot,
            "priority": args.priority,
            "interval": args.interval,
        },
        "summary": {
            "total_events": len(events),
            "malformed_records": malformed,
            "first_event": (
                events[0].timestamp.isoformat()
                if events else None
            ),
            "last_event": (
                events[-1].timestamp.isoformat()
                if events else None
            ),
            "errors": sum(
                event.priority <= 3 for event in events
            ),
            "warnings": priorities.get(4, 0),
            "unique_units": len({
                event.unit for event in events
            }),
            "unique_boots": len({
                event.boot_id for event in events
            }),
        },
        "health": calculate_health(events),
        "priorities": {
            PRIORITY_NAMES.get(priority, str(priority)): count
            for priority, count in sorted(priorities.items())
        },
        "categories": dict(categories.most_common()),
        "identifiers": dict(
            identifiers.most_common(args.top)
        ),
        "units": analyze_units(events, args.top),
        "boots": analyze_boots(events),
        "repeated_messages": repeated_messages(
            events,
            args.repeat_threshold,
            args.top,
        ),
        "bursts": detect_bursts(
            events,
            args.interval,
            args.burst_threshold,
        ),
        "anomalies": detect_anomalies(
            events,
            args.interval,
            args.sigma,
        ),
    }

    if args.include_events:
        report["events"] = [
            event.to_dict() for event in events
        ]

    return report


def print_section(name):
    print()
    print(name)
    print("-" * len(name))


def print_table(headers, rows):
    rows = [
        [str(value) for value in row]
        for row in rows
    ]

    widths = [
        max(
            len(str(header)),
            *(len(row[index]) for row in rows),
        )
        for index, header in enumerate(headers)
    ]

    print(
        "  ".join(
            str(header).ljust(widths[index])
            for index, header in enumerate(headers)
        )
    )

    print(
        "  ".join("-" * width for width in widths)
    )

    for row in rows:
        print(
            "  ".join(
                value.ljust(widths[index])
                for index, value in enumerate(row)
            )
        )


def render_text(report):
    summary = report["summary"]

    print("JOURNAL FORENSICS")
    print("=" * 64)
    print(f"Host:       {report['hostname']}")
    print(f"Generated:  {report['generated_at']}")
    print(f"Events:     {summary['total_events']}")
    print(f"Errors:     {summary['errors']}")
    print(f"Warnings:   {summary['warnings']}")
    print(f"Units:      {summary['unique_units']}")
    print(f"Boots:      {summary['unique_boots']}")
    print(f"Malformed:  {summary['malformed_records']}")

    health = report["health"]

    print_section("Observed Severity")
    print(f"Score: {health['score']}")
    print(f"Level: {health['level']}")
    print(f"Note:  {health['reason']}")

    print_section("Event Categories")

    if report["categories"]:
        print_table(
            ["Category", "Count"],
            list(report["categories"].items()),
        )
    else:
        print("No classified events")

    print_section("Top Units")

    if report["units"]:
        print_table(
            ["Unit", "Events", "Errors", "Warnings"],
            [
                [
                    unit["unit"],
                    unit["events"],
                    unit["errors"],
                    unit["warnings"],
                ]
                for unit in report["units"]
            ],
        )
    else:
        print("No units available")

    print_section("Boot Sessions")

    if report["boots"]:
        print_table(
            ["Boot ID", "Events", "Errors"],
            [
                [
                    boot["boot_id"][:16],
                    boot["events"],
                    boot["errors"],
                ]
                for boot in report["boots"]
            ],
        )
    else:
        print("No boot information")

    print_section("Repeated Messages")

    if report["repeated_messages"]:
        for item in report["repeated_messages"]:
            print(
                f"{item['count']:>6}  "
                f"{item['unit']}  "
                f"{item['signature'][:110]}"
            )
    else:
        print("No repeated messages above threshold")

    print_section("Event Bursts")

    if report["bursts"]:
        for burst in report["bursts"]:
            print(
                f"{burst['start']}  "
                f"{burst['events']} events"
            )
    else:
        print("No bursts detected")

    print_section("Statistical Anomalies")

    if report["anomalies"]:
        for anomaly in report["anomalies"]:
            print(
                f"{anomaly['start']}  "
                f"events={anomaly['events']}  "
                f"z={anomaly['z_score']}"
            )
    else:
        print("No statistical anomalies detected")


def export_json(report, destination):
    content = json.dumps(
        report,
        indent=2,
        ensure_ascii=False,
    )

    if destination:
        Path(destination).write_text(
            content + "\n",
            encoding="utf-8",
        )
    else:
        print(content)


def export_jsonl(events, destination):
    if destination:
        with open(destination, "w", encoding="utf-8") as stream:
            for event in events:
                stream.write(
                    json.dumps(
                        event.to_dict(),
                        ensure_ascii=False,
                    ) + "\n"
                )
    else:
        for event in events:
            print(
                json.dumps(
                    event.to_dict(),
                    ensure_ascii=False,
                )
            )


def export_csv(events, destination):
    fields = [
        "timestamp",
        "priority",
        "priority_name",
        "unit",
        "identifier",
        "pid",
        "boot_id",
        "message",
        "categories",
    ]

    if destination:
        stream = open(
            destination,
            "w",
            newline="",
            encoding="utf-8",
        )
    else:
        stream = sys.stdout

    try:
        writer = csv.DictWriter(
            stream,
            fieldnames=fields,
        )

        writer.writeheader()

        for event in events:
            record = event.to_dict()
            record["categories"] = ",".join(
                record["categories"]
            )
            writer.writerow(record)
    finally:
        if destination:
            stream.close()


def build_parser():
    parser = argparse.ArgumentParser(
        prog="journal-forensics",
        description=(
            "Systemd journal forensic analysis and "
            "event correlation utility"
        ),
    )

    parser.add_argument("--since", default="24 hours ago")
    parser.add_argument("--until")
    parser.add_argument("--unit", action="append")
    parser.add_argument("--boot")
    parser.add_argument("--priority", type=int, choices=range(8))
    parser.add_argument("--lines", type=int)
    parser.add_argument("--directory")
    parser.add_argument("--user", action="store_true")
    parser.add_argument("--search")
    parser.add_argument(
        "--category",
        action="append",
        choices=sorted(PATTERNS),
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "jsonl", "csv"],
        default="text",
    )
    parser.add_argument("--output")
    parser.add_argument("--top", type=int, default=15)
    parser.add_argument("--interval", type=int, default=60)
    parser.add_argument(
        "--burst-threshold",
        type=int,
        default=30,
    )
    parser.add_argument(
        "--repeat-threshold",
        type=int,
        default=5,
    )
    parser.add_argument("--sigma", type=float, default=2.0)
    parser.add_argument("--include-events", action="store_true")
    parser.add_argument("--no-redact", action="store_true")

    return parser


def validate_args(parser, args):
    for name in (
        "top",
        "interval",
        "burst_threshold",
        "repeat_threshold",
    ):
        if getattr(args, name) <= 0:
            parser.error(f"--{name.replace('_', '-')} must be positive")

    if not math.isfinite(args.sigma) or args.sigma <= 0:
        parser.error("--sigma must be finite and positive")

    if args.lines is not None and args.lines <= 0:
        parser.error("--lines must be positive")

    if args.search:
        try:
            re.compile(args.search)
        except re.error as error:
            parser.error(f"Invalid search expression: {error}")


def main():
    parser = build_parser()
    args = parser.parse_args()

    validate_args(parser, args)

    try:
        events, malformed = load_journal(args)

        report = build_report(
            events,
            malformed,
            args,
        )

        if args.format == "text":
            if args.output:
                original = sys.stdout

                try:
                    with open(
                        args.output,
                        "w",
                        encoding="utf-8",
                    ) as stream:
                        sys.stdout = stream
                        render_text(report)
                finally:
                    sys.stdout = original
            else:
                render_text(report)

        elif args.format == "json":
            export_json(report, args.output)

        elif args.format == "jsonl":
            export_jsonl(events, args.output)

        elif args.format == "csv":
            export_csv(events, args.output)

        return 0

    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        return 130

    except (
        RuntimeError,
        OSError,
        ValueError,
    ) as error:
        print(
            f"journal-forensics: {error}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
