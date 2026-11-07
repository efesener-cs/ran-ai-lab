"""Streaming, schema-preserving union for compact CSV source tables.

This utility only concatenates rows and adds source/cohort metadata. It does not
rename columns, infer labels, or combine tables with different observational units.
"""

from __future__ import annotations

import csv
import hashlib
import os
import shutil
from pathlib import Path
from typing import Iterable, Mapping, Sequence


METADATA_FIELDS = ("__cohort", "__source_table", "__split", "__row_unit")
MIN_FREE_BYTES = 8 * 1024**3


def _inspect_source(path: Path) -> tuple[list[str], int, str]:
    """Return header, data row count, and SHA256 without retaining rows."""
    digest = hashlib.sha256()
    with path.open("rb") as raw:
        for chunk in iter(lambda: raw.read(1024 * 1024), b""):
            digest.update(chunk)

    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.reader(stream)
        try:
            header = next(reader)
        except StopIteration as exc:
            raise ValueError(f"CSV source is empty: {path}") from exc
        if not header or any(name == "" for name in header):
            raise ValueError(f"CSV source has an empty column name: {path}")
        if len(set(header)) != len(header):
            raise ValueError(f"CSV source has duplicate column names: {path}")
        count = 0
        for row in reader:
            if len(row) != len(header):
                raise ValueError(
                    f"CSV row {count + 2} in {path} has {len(row)} fields; "
                    f"expected {len(header)}"
                )
            count += 1
    return header, count, digest.hexdigest()


def merge_tables(
    sources: Iterable[tuple[Path, Mapping[str, str]]],
    target: Path,
    *,
    metadata_fields: Sequence[str] = METADATA_FIELDS,
) -> dict[str, object]:
    """Stream a deterministic CSV union and return source/output provenance.

    ``sources`` is an ordered iterable of ``(Path, metadata)`` pairs. The output
    begins with ``metadata_fields``, followed by the stable first-seen union of
    source headers. Missing source columns are written as empty strings. Metadata
    must supply every metadata field for every source.

    Existing targets and ``<target>.partial`` files are never overwritten. A
    failed write leaves its partial file in place for inspection or recovery.
    """
    target = Path(target)
    source_list = [(Path(path), dict(metadata)) for path, metadata in sources]
    if not source_list:
        raise ValueError("At least one source table is required")

    fields = tuple(metadata_fields)
    if len(set(fields)) != len(fields) or any(not name for name in fields):
        raise ValueError("metadata_fields must contain unique, non-empty names")
    for name in fields:
        if not name.startswith("__"):
            raise ValueError(f"Metadata field must use the reserved __ prefix: {name}")

    if target.exists():
        raise FileExistsError(f"Refusing to overwrite target: {target}")
    partial = target.with_name(target.name + ".partial")
    if partial.exists():
        raise FileExistsError(f"Refusing to overwrite partial file: {partial}")

    inspected = []
    union_header: list[str] = []
    for path, metadata in source_list:
        for name in fields:
            if name not in metadata:
                raise ValueError(f"Missing metadata field {name!r} for {path}")
        header, count, digest = _inspect_source(path)
        collisions = set(header).intersection(fields)
        if collisions:
            raise ValueError(
                f"Source columns collide with metadata fields in {path}: "
                + ", ".join(sorted(collisions))
            )
        inspected.append((path, metadata, header, count, digest))
        for name in header:
            if name not in union_header:
                union_header.append(name)

    total_rows = sum(item[3] for item in inspected)
    target.parent.mkdir(parents=True, exist_ok=True)
    available = shutil.disk_usage(target.parent).free
    if available < MIN_FREE_BYTES:
        raise OSError(
            f"Insufficient free disk space: {available} bytes available; "
            f"at least {MIN_FREE_BYTES} bytes required"
        )

    output_header = [*fields, *union_header]
    output_digest = hashlib.sha256()
    written = 0
    with partial.open("x", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(output_header)
        union_indices = [
            {name: index for index, name in enumerate(source_header)}
            for _, _, source_header, _, _ in inspected
        ]
        for source_index, (path, metadata, source_header, _, _) in enumerate(inspected):
            index_by_name = union_indices[source_index]
            row_indices = [index_by_name.get(name) for name in union_header]
            with path.open("r", encoding="utf-8-sig", newline="") as source_stream:
                reader = csv.reader(source_stream)
                if next(reader, None) != source_header:
                    raise ValueError(f"CSV header changed while merging: {path}")
                for row in reader:
                    if len(row) != len(source_header):
                        raise ValueError(f"CSV row width changed while merging: {path}")
                    writer.writerow(
                        [metadata[name] for name in fields]
                        + [row[index] if index is not None else "" for index in row_indices]
                    )
                    written += 1
                    if written % 100_000 == 0:
                        available = shutil.disk_usage(target.parent).free
                        if available < MIN_FREE_BYTES:
                            raise OSError(
                                f"Free disk space fell below {MIN_FREE_BYTES} bytes "
                                f"after {written} rows ({available} bytes available)"
                            )
        stream.flush()
        os.fsync(stream.fileno())

    with partial.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            output_digest.update(chunk)
    if written != total_rows:
        raise RuntimeError(f"Output row count mismatch: wrote {written}, expected {total_rows}")
    if target.exists():
        raise FileExistsError(f"Refusing to overwrite target: {target}")
    os.replace(partial, target)

    return {
        "sources": [
            {"path": str(path), "rows": count, "sha256": digest}
            for path, _, _, count, digest in inspected
        ],
        "rows": written,
        "sha256": output_digest.hexdigest(),
        "header": output_header,
    }
