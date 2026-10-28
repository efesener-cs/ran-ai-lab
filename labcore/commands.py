"""One CLI registry and one subprocess command format."""
import sys
from labcore.paths import ROOT

COMMANDS = {
    'build_csv': 'datasets.build_csv',
    'build_offline': 'scenario.build_offline',
    'check_ai_shadow': 'checks.check_ai_shadow',
    'check_control': 'checks.check_control',
    'check_evasion': 'checks.check_evasion',
    'check_live': 'checks.check_live',
    'collect_ai_data': 'ai.collect_ai_data',
    'collect_campaign': 'simulation.collect_campaign',
    'evaluate_replay': 'ai.evaluate_replay',
    'export_dataset': 'datasets.export_dataset',
    'run_adversarial_suite': 'simulation.run_adversarial_suite',
    'run_controlled': 'simulation.run_controlled',
    'run_experiment': 'simulation.run_experiment',
    'run_docker': 'simulation.run_docker',
    'run_live': 'simulation.run_live',
    'run_scenario': 'simulation.run_scenario',
    'shadow_ai': 'ai.shadow_ai',
    'shadow_stream': 'ai.shadow_stream',
    'train_ai': 'ai.train',
}


def command(name, root=ROOT):
    name = name.removesuffix('.py')
    if name not in COMMANDS:
        raise ValueError('Unknown lab command: ' + name)
    return [sys.executable, str(root / 'lab.py'), name]
