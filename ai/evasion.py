"""Bounded SINR telemetry evasion; exact optima apply only to clipped residual Ridge."""
import copy
import math
import random

MODES = {'none', 'random', 'bias', 'fgsm', 'pgd', 'exact'}
ACCESS = {'two_cell', 'target_only', 'best_only'}


def shifted(observation, delta, previous_delta):
    """Bias all samples in a window and consistently update the tainted history."""
    out = {**observation, 'features': list(observation['features'])}
    out['current'] += delta
    out['features'][0] += delta
    out['features'][1] += delta
    out['features'][3] += delta - previous_delta
    return out


def score(model, observation):
    return model.predict([observation['features']], [observation['current']])[0]


def residual(model, observation):
    p = model.parameters
    total = p['bias']
    for i, value in enumerate(observation['features']):
        if not math.isfinite(value):
            value = p['median'][i]
        total += (value - p['mean'][i]) / p['scale'][i] * p['weights'][i]
    return total


def bias_slope(model):
    return sum(model.parameters['weights'][i] / model.parameters['scale'][i]
               for i in (0, 1, 3))


def derivative(model, observation):
    """Derivative away from clipping kinks; the direct current-SINR path remains."""
    if abs(residual(model, observation)) >= model.parameters['max_forecast_change_db']:
        return 1.0
    return 1.0 + bias_slope(model)


def exact_delta(model, observation, previous_delta, lower, upper, maximize=True):
    """Global one-window optimum: endpoints and both residual clipping breakpoints.

    History and attacked cells are fixed. This is not a multi-step policy/QoS optimum.
    The forecast is separable across cells, so two one-dimensional optima solve
    the target-minus-best margin exactly for the configured access restriction.
    """
    if model.parameters.get('algorithm') != 'residual_ridge':
        raise ValueError('Exact optimizer requires residual_ridge')
    if lower > upper:
        raise ValueError('Empty bias interval')
    candidates = {lower, upper, max(lower, min(upper, 0.0))}
    slope = bias_slope(model)
    if slope:
        intercept = residual(model, shifted(observation, 0, previous_delta))
        limit = model.parameters['max_forecast_change_db']
        for boundary in (-limit, limit):
            delta = (boundary - intercept) / slope
            if lower <= delta <= upper:
                candidates.add(delta)
    direction = 1 if maximize else -1
    return max(sorted(candidates), key=lambda delta: (
        direction * score(model, shifted(observation, delta, previous_delta)), -abs(delta)))


def validate(config):
    if config.get('mode') not in MODES:
        raise ValueError('Unknown evasion mode')
    eps = float(config.get('epsilon_db', 0))
    if not math.isfinite(eps) or not 0 <= eps <= 5:
        raise ValueError('epsilon_db must be 0..5')
    if config.get('access', 'two_cell') not in ACCESS:
        raise ValueError('Unknown attack access')
    for name, default, maximum in [('steps', 10, 100), ('restarts', 5, 100)]:
        value = config.get(name, default)
        if isinstance(value, bool) or int(value) != value or not 1 <= int(value) <= maximum:
            raise ValueError(name + ' must be an integer in 1..100')
    alpha = float(config.get('step_size_db', 2 * eps / config.get('steps', 10)))
    if not math.isfinite(alpha) or alpha < 0:
        raise ValueError('Invalid PGD step size')
    if 'max_step_db' in config:
        slew = float(config['max_step_db'])
        if not math.isfinite(slew) or slew < 0:
            raise ValueError('max_step_db must be finite and nonnegative')
    if 'robust_budget_db' in config:
        budget = float(config['robust_budget_db'])
        if not math.isfinite(budget) or not 0 <= budget <= 5:
            raise ValueError('robust_budget_db must be 0..5')
    ids = set()
    for event in config.get('events', []):
        start, end = float(event['start_s']), float(event['end_s'])
        if not math.isfinite(start + end) or start < 0 or end <= start or int(event['ue_imsi']) < 1:
            raise ValueError('Invalid evasion event')
        if event['id'] in ids:
            raise ValueError('Duplicate evasion event ID')
        ids.add(event['id'])


class Evasion:
    def __init__(self, model, config):
        validate(config)
        self.model = model
        self.config = copy.deepcopy(config)
        self.previous = {}

    def transform(self, observations):
        groups = {}
        for observation in observations:
            groups.setdefault((observation['run_id'], observation['ue'], observation['tick']), []).append(observation)
        changed, audit = [], []
        mode = self.config['mode']
        eps = float(self.config.get('epsilon_db', 0))
        access = self.config.get('access', 'two_cell')
        for key, items in sorted(groups.items(), key=lambda pair: (pair[0][0], pair[0][2], pair[0][1])):
            items = sorted(items, key=lambda o: o['cell'])
            now = items[0]['decision_time_s']
            events = [e for e in self.config.get('events', [])
                      if int(e['ue_imsi']) == key[1] and float(e['start_s']) <= now < float(e['end_s'])]
            active = bool(events) and mode != 'none' and not items[0]['warmup']
            clean = [score(self.model, o) for o in items]
            ranking = sorted(range(len(items)), key=lambda i: (-clean[i], items[i]['cell']))
            best = ranking[0]
            target = ranking[1] if len(ranking) > 1 else best
            previous = []
            for o in items:
                prior = self.previous.get((o['run_id'], o['ue'], o['cell']))
                previous.append(prior[1] if prior and prior[0] == o['tick'] - 1 else 0.0)
            support = ({best, target} if access == 'two_cell' else
                       {target} if access == 'target_only' else {best}) if best != target else set()
            bounds = [(0.0, 0.0)] * len(items)
            if active:
                for i in support:
                    lower, upper = -eps, eps
                    if 'max_step_db' in self.config:
                        slew = float(self.config['max_step_db'])
                        lower, upper = max(lower, previous[i] - slew), min(upper, previous[i] + slew)
                    bounds[i] = (lower, upper)
            deltas = [max(lo, min(hi, 0.0)) for lo, hi in bounds]
            rng = random.Random(f"{self.config.get('seed', 311)}:{key[1]}:{key[2]}")
            def margin(values):
                return (score(self.model, shifted(items[target], values[target], previous[target])) -
                        score(self.model, shifted(items[best], values[best], previous[best])))
            optimum = list(deltas)
            if active:
                for i in sorted(support):
                    lo, hi = bounds[i]
                    optimum[i] = exact_delta(self.model, items[i], previous[i], lo, hi, i == target)
                if mode in {'random', 'bias', 'exact'}:
                    for i in sorted(support):
                        lo, hi = bounds[i]
                        if mode == 'exact':
                            deltas[i] = optimum[i]
                        elif mode == 'bias':
                            # Domain heuristic; uses ranking but not model gradients/weights.
                            deltas[i] = hi if i == target else lo
                        else:
                            deltas[i] = rng.choice([lo, hi])
                else:
                    steps = 1 if mode == 'fgsm' else int(self.config.get('steps', 10))
                    alpha = eps if mode == 'fgsm' else float(self.config.get('step_size_db', 2 * eps / steps))
                    restarts = 1 if mode == 'fgsm' else int(self.config.get('restarts', 5))
                    best_margin = margin(deltas)
                    for restart in range(restarts):
                        candidate = list(deltas) if restart == 0 else [rng.uniform(lo, hi) for lo, hi in bounds]
                        value = margin(candidate)
                        if value > best_margin:
                            deltas, best_margin = list(candidate), value
                        for _ in range(steps):
                            for i in sorted(support):
                                gradient = (1 if i == target else -1) * derivative(
                                    self.model, shifted(items[i], candidate[i], previous[i]))
                                sign = 1 if gradient > 0 else -1 if gradient < 0 else 0
                                lo, hi = bounds[i]
                                candidate[i] = max(lo, min(hi, candidate[i] + alpha * sign))
                            value = margin(candidate)
                            if value > best_margin:
                                deltas, best_margin = list(candidate), value
            optimal_margin = margin(optimum)
            achieved_margin = margin(deltas)
            for i, o in enumerate(items):
                observed = shifted(o, deltas[i], previous[i])
                affected = abs(deltas[i]) > 1e-10 or abs(previous[i]) > 1e-10
                record = dict(run_id=o['run_id'], decision_time_s=now, ue_imsi=o['ue'], nr_cell_id=o['cell'],
                    mode=mode, is_warmup=int(o['warmup']),event_active=int(active), input_perturbed=int(affected), access=access,
                    attack_accessible=int(active and i in support), bias_lower_db=bounds[i][0], bias_upper_db=bounds[i][1],
                    epsilon_db=eps if mode != 'none' else 0.0, delta_sinr_db=deltas[i], previous_delta_db=previous[i],
                    raw_sinr_mean_db=o['current'], model_sinr_mean_db=observed['current'],
                    clean_prediction_db=clean[i], observed_prediction_db=score(self.model, observed),
                    clean_best_cell=items[best]['cell'], attack_target_cell=items[target]['cell'] if active else '',
                    achieved_target_margin_db=achieved_margin, optimal_target_margin_db=optimal_margin,
                    attack_optimality_gap_db=max(0.0, optimal_margin - achieved_margin),
                    active_event_ids=';'.join(str(e['id']) for e in events) if active else '')
                for j, name in enumerate(self.model.parameters['features']):
                    a, b = o['features'][j], observed['features'][j]
                    record['clean_' + name] = a if math.isfinite(a) else ''
                    record['model_' + name] = b if math.isfinite(b) else ''
                audit.append(record)
                changed.append(observed)
                self.previous[(o['run_id'], o['ue'], o['cell'])] = (o['tick'], deltas[i])
        return changed, audit
