#!/usr/bin/env python3
"""Convert ns-3 traces without dependencies; windows are [start, end)."""
import argparse
import csv
import hashlib
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path


def lines(path):
    with path.open() as stream:
        for line in stream:
            if line.strip() and not line.startswith('%'):
                yield line.split()


def write_csv(path, rows):
    if not rows:
        raise ValueError(f'No rows for {path}')
    with path.open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_dir', type=Path)
    parser.add_argument('--window-ms', type=int, default=100)
    parser.add_argument('--duration-s', type=float, default=2)
    args = parser.parse_args()
    if args.window_ms <= 0 or args.duration_s <= 0:
        parser.error('Window and duration must be positive')
    root = args.run_dir.resolve()
    run_id = root.parent.name if root.name == 'raw' else root.name
    out = (root.parent if root.name == 'raw' else root) / 'csv'
    out.mkdir(exist_ok=True)
    width = args.window_ms / 1000
    sinr = defaultdict(list)
    phy = defaultdict(list)
    events = defaultdict(list)
    ues, cells = set(), set()
    def bucket(t):
        return math.floor(round(float(t) / width, 9))
    for t, ue, cell, value in lines(root / 'MmWaveSinrTime.txt'):
        ue, cell = int(ue), int(cell)
        ues.add(ue)
        cells.add(cell)
        sinr[bucket(t), ue, cell].append(float(value))
    # PHY traces identify cell/RNTI, not IMSI. Aggregate at cell level only.
    for row in lines(root / 'RxPacketTrace.txt'):
        if row[0] == 'DL':
            phy[bucket(row[1]), int(row[7])].append(row)
    for t, ue, cell, rnti in lines(root / 'CellIdStats.txt'):
        events[int(ue)].append((float(t), int(cell), int(rnti)))
    for ev in events.values():
        ev.sort()
    rows = []
    for tick in range(math.ceil(args.duration_s / width)):
        start, end = tick * width, min((tick + 1) * width, args.duration_s)
        for ue in sorted(ues):
            past = [ev for ev in events[ue] if ev[0] < end]
            active = past[-1][1] if past else ''
            # Count actual recorded path changes, excluding duplicate notifications.
            switches, previous = 0, None
            for t, cell, _ in events[ue]:
                if t >= end:
                    break
                if start <= t and previous is not None and cell != previous:
                    switches += 1
                previous = cell
            for cell in sorted(cells):
                values = sinr[tick, ue, cell]
                records = phy[tick, cell]
                good_bytes = sum(int(r[10]) for r in records if int(r[14]) == 0)
                row = dict(run_id=run_id, window_start_s=round(start, 9),
                           window_end_s=round(end, 9), ue_imsi=ue, nr_cell_id=cell,
                           last_recorded_path_cell_id=active,
                           matches_last_recorded_path=int(active == cell) if active != '' else '',
                           ue_recorded_path_changes=switches,
                           sinr_sample_count=len(values),
                           sinr_mean_db=statistics.mean(values) if values else '',
                           sinr_std_db=statistics.pstdev(values) if values else '',
                           sinr_min_db=min(values) if values else '',
                           sinr_max_db=max(values) if values else '',
                           sinr_last_db=values[-1] if values else '',
                           cell_dl_tb_count=len(records),
                           cell_dl_corrupt_tb_count=sum(int(r[14]) for r in records),
                           cell_dl_corrupt_fraction=statistics.mean(int(r[14]) for r in records) if records else '',
                           cell_dl_tb_bytes=sum(int(r[10]) for r in records),
                           cell_dl_successful_tb_bytes=good_bytes,
                           cell_dl_successful_tb_mbps=good_bytes * 8 / (end - start) / 1e6,
                           cell_dl_mcs_mean=statistics.mean(int(r[11]) for r in records) if records else '',
                           cell_dl_rv_mean=statistics.mean(int(r[12]) for r in records) if records else '',
                           cell_dl_rx_sinr_mean_db=statistics.mean(float(r[13]) for r in records) if records else '',
                           cell_dl_tbler_mean=statistics.mean(float(r[15]) for r in records) if records else '',
                           attack_present=0, attack_type='none',
                           traffic_profile='scenario_zero_fixed_udp')
                rows.append(row)
    write_csv(out / f'ran_features_{args.window_ms}ms.csv', rows)
    # Preserve original bearer interval; do not repeat a 250ms measurement in 100ms bins.
    bearer = []
    for layer, filename in [('pdcp', 'DlPdcpStats.txt'), ('rlc', 'DlRlcStats.txt')]:
        for r in lines(root / filename):
            start, end = float(r[0]), float(r[1])
            bearer.append(dict(run_id=run_id, layer=layer,
                interval_start_s=start, interval_end_s=end,
                cell_id=int(r[2]), ue_imsi=int(r[3]), rnti=int(r[4]), lcid=int(r[5]),
                tx_pdus=int(r[6]), tx_bytes=int(r[7]), rx_pdus=int(r[8]), rx_bytes=int(r[9]),
                rx_mbps=int(r[9])*8/(end-start)/1e6,
                delay_mean_s=float(r[10]), delay_std_s=float(r[11]),
                delay_min_s=float(r[12]), delay_max_s=float(r[13])))
    write_csv(out / 'bearer_intervals.csv', bearer)
    summary = dict(row_unit='UE x measured NR cell x time window',
        window_ms=args.window_ms, duration_s=args.duration_s,
        rows=len(rows), columns=len(rows[0]), ues=len(ues), nr_cells=len(cells),
        sinr_input_samples=sum(map(len, sinr.values())),
        sinr_output_samples=sum(r['sinr_sample_count'] for r in rows),
        missing_sinr_rows=sum(r['sinr_sample_count'] == 0 for r in rows),
        bearer_rows=len(bearer),
        missing_values={k:sum(r[k] == '' for r in rows) for k in rows[0]},
        source_sha256={name:hashlib.sha256((root/name).read_bytes()).hexdigest()
            for name in ['MmWaveSinrTime.txt','RxPacketTrace.txt','CellIdStats.txt','DlPdcpStats.txt','DlRlcStats.txt']},
        caveats=['Cell PHY features repeat across UEs; they are cell context, not UE throughput.',
                 'Last recorded path is event-derived, not a complete serving-cell history.',
                 'Successful TB rate is not application goodput; retransmissions may be counted.',
                 'No attack was executed. Labels describe this baseline run only.',
                 'Two-second pilot includes startup; not a training-ready dataset.'])
    assert summary['sinr_input_samples'] == summary['sinr_output_samples']
    (out / 'quality_report.json').write_text(json.dumps(summary, indent=2)+'\n')
    print(json.dumps({k:summary[k] for k in ['rows','columns','ues','nr_cells','sinr_input_samples','missing_sinr_rows','bearer_rows']},indent=2))
    print(out)

if __name__ == '__main__':
    main()
