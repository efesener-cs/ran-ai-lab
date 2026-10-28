"""Small deterministic traces generated for tests, independent of saved experiments."""
import contextlib
import csv
import io
import json

from datasets.export_dataset import main as export_dataset


def write_telemetry(root, ues=6, windows=30):
    raw = root / 'raw'
    raw.mkdir(parents=True)
    sinr, phy, paths, applications = [], [], [], []
    for ue in range(1, ues + 1):
        paths.append(f'0.0 {ue} 2 1\n')
    for tick in range(windows):
        for cell in [2, 3, 4, 5]:
            row = ['DL', str(tick / 10 + .04), '0', '0', '0', '0', '0',
                   str(cell), '0', '0', '100', '1', '0', '10', str(tick % 3 == 0 and 1 or 0), '0']
            phy.append(' '.join(row) + '\n')
            for ue in range(1, ues + 1):
                for offset, adjustment in [(.02, -.1), (.07, .1)]:
                    value = 10 + cell * .2 + ue * .03 + tick * .1 + adjustment
                    sinr.append(f'{tick / 10 + offset:.9f} {ue} {cell} {value:.9f}\n')
        for ue in range(1, ues + 1):
            applications.append(dict(window_start_s=tick / 10, window_end_s=(tick + 1) / 10,
                ue_imsi=ue, traffic_profile='udp_telemetry', direction='UL', rx_bytes=100,
                app_goodput_mbps=.008, x_m=ue, y_m=tick, speed_mps=1, is_warmup=int(tick < 10)))
    for name, rows in [('MmWaveSinrTime.txt', sinr), ('RxPacketTrace.txt', phy), ('CellIdStats.txt', paths)]:
        (raw / name).write_text(''.join(rows))
    for name in ['DlPdcpStats.txt', 'DlRlcStats.txt']:
        (raw / name).write_text('% Synthetic header-only bearer trace\n')
    with (raw / 'app_kpi.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(applications[0]))
        writer.writeheader()
        writer.writerows(applications)
    (root / 'run_status.json').write_text(json.dumps(dict(status='complete',
        simulation_exit_code=0, live_ric_verified=True, configuration=dict(seed=101))))
    with contextlib.redirect_stdout(io.StringIO()):
        export_dataset([str(root), '--duration', str(windows / 10)])
    return root
