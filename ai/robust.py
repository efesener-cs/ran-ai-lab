"""Conservative forecast envelopes for bounded current and previous SINR bias.

A certificate concerns a one-step score gain, not throughput, handover success,
or policy state after a different trajectory. It assumes the fitted model and
all other telemetry features are trusted. Both SINR biases may vary independently.
"""
import math
from ai.evasion import exact_delta, score, shifted


def forecast_interval(model, observation, budget_db):
    budget = float(budget_db)
    if not math.isfinite(budget) or budget < 0 or budget > 5:
        raise ValueError('Robust budget must be finite and in 0..5 dB')
    values = []
    # For fixed current bias the forecast is monotone in previous bias,
    # so its extrema occur at endpoints. Current-bias extrema include clip kinks.
    for previous in {-budget, budget}:
        for maximize in (False, True):
            delta = exact_delta(model, observation, previous, -budget, budget, maximize)
            values.append(score(model, shifted(observation, delta, previous)))
    return min(values), max(values)
