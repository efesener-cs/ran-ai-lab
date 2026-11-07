"""Append a verified native LTE resource reference to the two RAN CSV tables."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Iterable, Iterator, Mapping


RESOURCE_PROFILE = "GraphQ_TBFQ_group_weight_20_50_80"
WINDOW_UNIT = "UE application window"
DECISION_UNIT = "service-group resource decision"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json(path: Path) -> dict:
    with path.open(encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def _read_rows(path: Path) -> tuple[list[str], Iterator[dict[str, str]]]:
    stream = path.open(encoding="utf-8-sig", newline="")
    reader = csv.DictReader(stream)
    if not reader.fieldnames or len(set(reader.fieldnames)) != len(reader.fieldnames):
        stream.close()
        raise ValueError(f"Invalid CSV header: {path}")

    def generate() -> Iterator[dict[str, str]]:
        try:
            for row in reader:
                if None in row:
                    raise ValueError(f"Malformed row in {path}")
                yield row
        finally:
            stream.close()

    return list(reader.fieldnames), generate()


def _atomic_json(path: Path, value: Mapping[str, object]) -> None:
    partial = path.with_name(path.name + ".partial")
    if partial.exists():
        raise FileExistsError(f"Refusing to overwrite partial file: {partial}")
    with partial.open("x", encoding="utf-8", newline="") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(partial, path)


def _backup(path: Path, backup: Path, expected_sha: str | None = None) -> str:
    backup.parent.mkdir(parents=True, exist_ok=True)
    source_sha = _sha256(path)
    if expected_sha is not None and source_sha != expected_sha:
        raise RuntimeError(f"Base table changed since extension began: {path}")
    if backup.exists():
        if _sha256(backup) != source_sha:
            raise FileExistsError(f"Different immutable backup already exists: {backup}")
    else:
        os.link(path, backup)
    return source_sha


def _collection_sources(resource: Path) -> tuple[dict, list[dict]]:
    collection_path = resource / "collection.json"
    collection = _json(collection_path)
    if collection.get("state") != "complete":
        raise RuntimeError("Resource collection is not complete")
    verification_path = resource / "verification.json"
    if not verification_path.is_file() or not _json(verification_path).get("verified"):
        raise RuntimeError("Resource collection verification is missing or not verified")
    completed = collection.get("completed")
    if not isinstance(completed, list) or not completed:
        raise ValueError("Completed collection has no run list")
    runs = []
    for name in completed:
        run = resource / "runs" / str(name)
        status_path = run / "run_status.json"
        status = _json(status_path)
        if status.get("status") != "complete":
            raise RuntimeError(f"Incomplete run status: {status_path}")
        raw = run / "raw"
        required = [
            raw / "ran_windows.csv",
            raw / "resource_events.csv",
            raw / "decision_states.jsonl",
            raw / "control_dispatch.csv",
        ]
        if any(not path.is_file() for path in required):
            raise FileNotFoundError(f"Required resource run input missing under {raw}")
        runs.append({"name": str(name), "path": run, "status_path": status_path, "status": status})
    return collection, runs


def _labels(config: Mapping[str, object], active: bool) -> tuple[str, int, int, int, int]:
    labels = []
    attack = str(config.get("attack", "none"))
    if attack != "none":
        labels.append("fake_service_request" if attack in {"fake_request", "fake_requests"} else attack)
    model = str(config.get("model") or "").lower()
    if "reward_poison" in model or model == "reward_poison":
        labels.append("rl_reward_poison")
    if "backdoor" in model:
        labels.append("rl_policy_backdoor")
    flood = bool(config.get("traffic_overload") or config.get("flood"))
    if flood:
        labels.append("downlink_offered_load_flood")
    active_labels = labels if active else []
    return (
        ";".join(dict.fromkeys(active_labels)) or "none",
        int(active),
        int(active and bool(config.get("model")) and ("poison" in model or "backdoor" in model)),
        int(active and bool(config.get("fake_requests")) or (active and attack in {"fake_request", "fake_requests"})),
        int(active and flood),
    )


def _window_split(name: str) -> str:
    if name.startswith("explore-"):
        try:
            index = int(name.split("-", 1)[1])
        except ValueError:
            return "unknown"
        if 0 <= index <= 14:
            return "train"
        if 15 <= index <= 19:
            return "validation"
    if name.startswith("eval"):
        return "test"
    return "unknown"


def _resource_events(path: Path) -> dict[str, list[dict[str, str]]]:
    header, rows = _read_rows(path)
    required = {"sim_time_s", "ue_imsi", "service_group", "true_group_demand_mbps", "reported_group_demand_mbps", "configured_mbr_bps"}
    if not required.issubset(header):
        raise ValueError(f"Resource event schema missing {sorted(required - set(header))}: {path}")
    events: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        events.setdefault(row["ue_imsi"], []).append(row)
    for values in events.values():
        values.sort(key=lambda row: float(row["sim_time_s"]))
    return events


def _window_rows(run: dict) -> tuple[list[str], Iterator[dict[str, str]]]:
    raw = run["path"] / "raw"
    source = raw / "ran_windows.csv"
    header, rows = _read_rows(source)
    required = {"window_start_s", "window_end_s", "ue_imsi", "cell_id"}
    if not required.issubset(header):
        raise ValueError(f"Resource window schema missing {sorted(required - set(header))}: {source}")
    events = _resource_events(raw / "resource_events.csv")
    config = run["status"].get("configuration", {})
    name = run["name"]

    def generate() -> Iterator[dict[str, str]]:
        for row in rows:
            start, end = float(row["window_start_s"]), float(row["window_end_s"])
            active = start > 4.0
            attack_family, intervention_active, poisoned, spoofed, flood = _labels(config, active)
            ue_events = events.get(row["ue_imsi"], [])
            selected = None
            for event in ue_events:
                if float(event["sim_time_s"]) <= start:
                    selected = event
                else:
                    break
            allocation_inside = any(start < float(event["sim_time_s"]) <= end for event in ue_events)
            output = dict(row)
            output.update(
                __cohort="native_lte_resource_reference",
                __row_unit=WINDOW_UNIT,
                __split=_window_split(name),
                source_context_group="native-resource:seed" + str(config.get("seed", "")),
                run_id="resource-v1:" + name,
                attack_family=attack_family,
                intervention_active=intervention_active,
                policy_model_poisoned=poisoned,
                resource_request_spoofed=spoofed,
                offered_load_flood_active=flood,
                native_seed=config.get("seed", ""),
                native_policy=config.get("policy", ""),
                native_attack=config.get("attack", "none"),
                native_fake_requests=int(bool(config.get("fake_requests"))),
                native_traffic_overload=int(bool(config.get("traffic_overload") or config.get("flood"))),
                resource_configuration_changed_within_window=int(allocation_inside),
                handover_within_window=0,
            )
            if selected is not None:
                output.update(
                    configured_mbr_bps=int(float(selected["configured_mbr_bps"])),
                    service_group=selected["service_group"],
                    reported_group_demand_mbps=selected["reported_group_demand_mbps"],
                    true_group_demand_mbps_audit=selected["true_group_demand_mbps"],
                    resource_config_time_s=selected["sim_time_s"],
                )
            yield output

    return header, generate()


def _decision_rows(run: dict) -> tuple[list[str], Iterator[dict[str, str]]]:
    raw = run["path"] / "raw"
    states_path = raw / "decision_states.jsonl"
    dispatch_path = raw / "control_dispatch.csv"
    dispatch_header, dispatch_rows = _read_rows(dispatch_path)
    if not {"request_id", "status"}.issubset(dispatch_header):
        raise ValueError(f"Invalid dispatch schema: {dispatch_path}")
    dispatch = {row["request_id"]: row for row in dispatch_rows}
    config = run["status"].get("configuration", {})
    name = run["name"]
    sample_state = None
    with states_path.open(encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                sample_state = json.loads(line)
                break
    if sample_state is None or not isinstance(sample_state.get("state"), dict):
        raise ValueError(f"No decision-state records: {states_path}")
    state_keys = list(sample_state["state"])
    fields = [
        "__cohort", "__row_unit", "__split", "source_context_group", "run_id", "request_id",
        "decision_time_s", "action", "recommended_action", "target_profile", "recommended_profile",
        "target_cell", "ue_imsi", "attack_family", "intervention_active", "policy_model_poisoned",
        "resource_request_spoofed", "offered_load_flood_active", "native_seed", "native_policy",
        "native_attack", "native_fake_requests", "native_traffic_overload", "control_action_tampered",
        "controller_input_perturbed", "dispatch_status", "resource_profile",
    ]
    fields += ["true_" + key for key in state_keys]
    fields += ["observed_" + key for key in state_keys]

    def generate() -> Iterator[dict[str, str]]:
        with states_path.open(encoding="utf-8") as stream:
            for line in stream:
                if not line.strip():
                    continue
                record = json.loads(line)
                state = record["state"]
                observed = record.get("observed", {})
                time_s = float(state["time"])
                active = time_s >= 4.0
                attack_family, intervention_active, poisoned, spoofed, flood = _labels(config, active)
                target = record.get("target", "")
                recommended = record.get("recommended_target", "")
                action = record.get("action", "")
                request_id = str(state.get("step", ""))
                command = dispatch.get(request_id, {})
                perturbed = any(
                    str(state.get(key, "")) != str(observed.get(key, ""))
                    for key in state
                    if key in observed
                )
                output = {
                    "__cohort": "native_lte_resource_reference",
                    "__row_unit": DECISION_UNIT,
                    "__split": _window_split(name),
                    "source_context_group": "native-resource:seed" + str(config.get("seed", "")),
                    "run_id": "resource-v1:" + name,
                    "request_id": request_id,
                    "decision_time_s": str(state.get("time", "")),
                    "action": str(action),
                    "recommended_action": str(record.get("recommended_action", "")),
                    "target_profile": str(target),
                    "recommended_profile": str(recommended),
                    "target_cell": "",
                    "ue_imsi": "",
                    "attack_family": attack_family,
                    "intervention_active": str(intervention_active),
                    "policy_model_poisoned": str(poisoned),
                    "resource_request_spoofed": str(spoofed),
                    "offered_load_flood_active": str(flood),
                    "native_seed": str(config.get("seed", "")),
                    "native_policy": str(config.get("policy", "")),
                    "native_attack": str(config.get("attack", "none")),
                    "native_fake_requests": str(int(bool(config.get("fake_requests")))),
                    "native_traffic_overload": str(int(bool(config.get("traffic_overload") or config.get("flood")))),
                    "control_action_tampered": str(int(action == "allocate" and target != recommended)),
                    "controller_input_perturbed": str(int(perturbed)),
                    "dispatch_status": str(command.get("status", "")),
                    "resource_profile": RESOURCE_PROFILE,
                }
                output.update({"true_" + key: str(value) for key, value in state.items()})
                output.update({"observed_" + key: str(value) for key, value in observed.items()})
                yield output

    return fields, generate()


def _append_table(path: Path, new_fields: list[str], new_rows: Iterable[Mapping[str, object]]) -> dict[str, object]:
    old_header, old_rows = _read_rows(path)
    header = old_header + [name for name in new_fields if name not in old_header]
    partial = path.with_name(path.name + ".resource.partial")
    if partial.exists():
        raise FileExistsError(f"Refusing to overwrite partial file: {partial}")
    rows_written = 0
    with partial.open("x", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(header)
        old_indices = {name: index for index, name in enumerate(old_header)}
        with path.open(encoding="utf-8-sig", newline="") as old_stream:
            reader = csv.reader(old_stream)
            source_header = next(reader, None)
            if source_header != old_header:
                raise ValueError(f"Base header changed while reading: {path}")
            for row in reader:
                if len(row) != len(old_header):
                    raise ValueError(f"Malformed base row in {path}")
                writer.writerow([row[old_indices[name]] if name in old_indices else "" for name in header])
                rows_written += 1
        for row in new_rows:
            writer.writerow([str(row.get(name, "")) if row.get(name, "") is not None else "" for name in header])
            rows_written += 1
        stream.flush()
        os.fsync(stream.fileno())
    digest = _sha256(partial)
    os.replace(partial, path)
    return {"rows": rows_written, "sha256": digest, "columns": header}


def extend(delivery: Path, audit: Path, resource: Path) -> dict[str, object]:
    delivery, audit, resource = delivery.resolve(), audit.resolve(), resource.resolve()
    collection, runs = _collection_sources(resource)
    extension_path = audit / "resource_extension.json"
    export_path = audit / "export.json"
    if not export_path.is_file():
        raise FileNotFoundError(f"Base export audit is missing: {export_path}")
    export = _json(export_path)
    if export.get("state") != "complete":
        raise RuntimeError("Base CSV export is not complete")
    tables = export.get("tables")
    if not isinstance(tables, dict):
        raise ValueError("Base export audit lacks table entries")

    source_records = []
    for run in runs:
        paths = [
            run["status_path"],
            run["path"] / "raw/ran_windows.csv",
            run["path"] / "raw/resource_events.csv",
            run["path"] / "raw/decision_states.jsonl",
            run["path"] / "raw/control_dispatch.csv",
        ]
        source_records.extend({"path": str(path.resolve()), "sha256": _sha256(path)} for path in paths)
    resource_identity = {"collection": str((resource / "collection.json").resolve()), "sha256": _sha256(resource / "collection.json"), "sources": source_records}
    resource_id = hashlib.sha256(json.dumps(resource_identity, sort_keys=True).encode()).hexdigest()

    if extension_path.is_file():
        previous = _json(extension_path)
        if previous.get("state") == "complete" and previous.get("resource_id") == resource_id:
            for name, record in previous["updated_tables"].items():
                current = delivery / name
                if not current.is_file() or _sha256(current) != record["sha256"]:
                    raise RuntimeError(f"Previously extended output changed: {current}")
            return previous
        raise FileExistsError("A different or incomplete resource extension already exists")

    window_path = delivery / "ran_windows.csv"
    decision_path = delivery / "control_decisions.csv"
    for path in (window_path, decision_path):
        if not path.is_file():
            raise FileNotFoundError(path)
    base_stats = {path.name: tables.get(path.name) for path in (window_path, decision_path)}
    backups = {}
    for path in (window_path, decision_path):
        expected = None
        base_entry = tables.get(path.name)
        if isinstance(base_entry, dict):
            expected = base_entry.get("sha256")
        backup = audit / "base_native_backup" / path.name
        backups[path.name] = {"path": str(backup), "sha256": _backup(path, backup, expected)}

    window_fields: list[str] = []
    decision_fields: list[str] = []
    window_rows: list[dict[str, str]] = []
    decision_rows: list[dict[str, str]] = []
    for run in runs:
        fields, rows = _window_rows(run)
        window_fields += [name for name in fields if name not in window_fields]
        window_fields += [
            name for name in (
                "__cohort", "__row_unit", "__split", "source_context_group", "run_id", "attack_family",
                "intervention_active", "policy_model_poisoned", "resource_request_spoofed", "offered_load_flood_active",
                "native_seed", "native_policy", "native_attack", "native_fake_requests", "native_traffic_overload",
                "resource_configuration_changed_within_window", "configured_mbr_bps", "service_group",
                "reported_group_demand_mbps", "true_group_demand_mbps_audit", "resource_config_time_s", "handover_within_window",
            ) if name not in window_fields
        ]
        window_rows.extend(rows)
        fields, rows = _decision_rows(run)
        decision_fields += [name for name in fields if name not in decision_fields]
        decision_rows.extend(rows)

    # Capture immutable audit state before publishing either replacement.
    extension = {
        "state": "prepared",
        "resource_id": resource_id,
        "resource": str(resource),
        "collection_sha256": resource_identity["sha256"],
        "source_hashes": source_records,
        "base_stats": base_stats,
        "backups": backups,
    }
    _atomic_json(extension_path, extension)
    updated = {
        "ran_windows.csv": _append_table(window_path, window_fields, window_rows),
        "control_decisions.csv": _append_table(decision_path, decision_fields, decision_rows),
    }
    for name, record in updated.items():
        tables[name] = {"rows": record["rows"], "sha256": record["sha256"], "header": record["columns"]}
    _atomic_json(export_path, export)
    extension.update(state="complete", updated_tables=updated)
    _atomic_json(extension_path, extension)
    return extension


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--delivery", required=True, type=Path)
    parser.add_argument("--audit", required=True, type=Path)
    parser.add_argument("--resource", required=True, type=Path)
    args = parser.parse_args()
    result = extend(args.delivery, args.audit, args.resource)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
