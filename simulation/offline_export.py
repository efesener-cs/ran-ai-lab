"""Wait for a verified collection and publish a fresh compact local CSV view."""
import argparse
import json
from pathlib import Path
import time
from datasets.export_compact_kaggle import export_campaign


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--campaign',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args(argv)
    while True:
        plan=json.loads((a.campaign/'campaign.json').read_text())
        state=plan['state']
        if state=='complete':break
        if state not in ('prepared','running','resource_limited'):
            raise RuntimeError('Collection stopped before export: '+state)
        time.sleep(30)
    print(json.dumps(export_campaign(a.campaign,a.output),indent=2),flush=True)
    return 0


if __name__=='__main__':raise SystemExit(main())
