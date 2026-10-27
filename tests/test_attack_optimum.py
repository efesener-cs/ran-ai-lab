"""Focused regression tests for exact and iterative telemetry attacks."""
import math
import unittest

from ai.evasion import Evasion, exact_delta, score, shifted, validate
from ai.runtime import RuntimeForecaster


def make_model(weight=-2.0, bias=3.0, limit=1.0):
    features = ['sinr_mean_db', 'sinr_last_db', 'sinr_std_db', 'mean_change_db',
                'last_minus_mean_db', 'cell_dl_tb_count', 'cell_dl_corrupt_fraction',
                'cell_corrupt_fraction_missing']
    return RuntimeForecaster(dict(
        schema_version=1, algorithm='residual_ridge', features=features,
        median=[0.0] * 8, mean=[0.0] * 8, scale=[1.0] * 8,
        weights=[weight, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        bias=bias, max_forecast_change_db=limit))


def observation(cell, current, tick=11, time=1.2):
    return dict(run_id='synthetic', ue=1, tick=tick, decision_time_s=time,
                warmup=False, cell=cell, current_path_cell=cell,
                current=current, features=[0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0])


class ExactAttackTests(unittest.TestCase):
    def test_exact_delta_matches_dense_grid_for_negative_slope_and_interior_kink(self):
        model = make_model()
        obs = observation(7, 0.0)
        lo, hi, previous = -2.0, 2.0, 0.0
        exact = exact_delta(model, obs, previous, lo, hi, maximize=True)
        grid = [lo + (hi - lo) * i / 100000 for i in range(100001)]
        grid_best = max(grid, key=lambda d: score(model, shifted(obs, d, previous)))
        self.assertAlmostEqual(exact, 1.0, places=7)  # residual reaches +limit inside the box
        self.assertAlmostEqual(score(model, shifted(obs, exact, previous)),
                               score(model, shifted(obs, grid_best, previous)), places=5)
        self.assertAlmostEqual(exact_delta(model, obs, previous, lo, hi, maximize=False),
                               -2.0, places=7)

    def test_exact_mode_beats_iterative_margin_modes_at_same_history(self):
        model = make_model()
        # Cell 2 is clean best; cell 3 is the target. Both cells have the same
        # clipped, non-monotonic response; fixed prior deltas exercise history.
        obs = [observation(2, 0.0), observation(3, -0.2), observation(4, -10.0)]
        event = [dict(id='e', ue_imsi=1, start_s=1.0, end_s=2.0)]
        results = {}
        for mode in ('exact', 'fgsm', 'pgd'):
            config = dict(mode=mode, epsilon_db=2.0, steps=3, restarts=2,
                          seed=91, events=event)
            engine = Evasion(model, config)
            engine.previous.update({('synthetic', 1, 2): (10, 0.25),
                                    ('synthetic', 1, 3): (10, -0.15)})
            _, audit = engine.transform(obs)
            rows = {r['nr_cell_id']: r for r in audit}
            results[mode] = rows[3]['observed_prediction_db'] - rows[2]['observed_prediction_db']
            if mode == 'exact':
                for row in audit:
                    self.assertAlmostEqual(row['attack_optimality_gap_db'], 0.0, places=7)
        self.assertGreaterEqual(results['exact'] + 1e-8, results['fgsm'])
        self.assertGreaterEqual(results['exact'] + 1e-8, results['pgd'])

    def test_pgd_best_iterate_never_worse_than_zero_feasible_start(self):
        model = make_model()
        obs = [observation(2, 0.0), observation(3, -0.2)]
        cfg = dict(mode='pgd', epsilon_db=2.0, steps=1, restarts=4,
                   seed=12, events=[dict(id='e', ue_imsi=1, start_s=1, end_s=2)])
        _, audit = Evasion(model, cfg).transform(obs)
        rows = {r['nr_cell_id']: r for r in audit}
        achieved = rows[3]['observed_prediction_db'] - rows[2]['observed_prediction_db']
        zero_margin = rows[3]['clean_prediction_db'] - rows[2]['clean_prediction_db']
        self.assertGreaterEqual(achieved + 1e-10, zero_margin)

    def test_access_supports_and_zero_budget(self):
        model = make_model()
        obs = [observation(2, 0.0), observation(3, -0.2), observation(4, -10.0)]
        event = [dict(id='e', ue_imsi=1, start_s=1, end_s=2)]
        for access, expected_cells in [('target_only', {3}), ('best_only', {2})]:
            _, audit = Evasion(model, dict(mode='exact', access=access, epsilon_db=1,
                                           events=event)).transform(obs)
            self.assertEqual({r['nr_cell_id'] for r in audit if r['attack_accessible']}, expected_cells)
            for row in audit:
                if row['nr_cell_id'] not in expected_cells:
                    self.assertEqual(row['delta_sinr_db'], 0.0)
        out, audit = Evasion(model, dict(mode='exact', epsilon_db=0, events=event)).transform(obs)
        self.assertEqual(out, obs)
        self.assertTrue(all(r['delta_sinr_db'] == 0 for r in audit))

    def test_slew_limit_only_applies_while_event_active_then_resets(self):
        model = make_model()
        first = [observation(2, 0.0, 11, 1.2), observation(3, -0.2, 11, 1.2)]
        second = [observation(2, 0.0, 12, 2.0), observation(3, -0.2, 12, 2.0)]
        cfg = dict(mode='exact', epsilon_db=2.0, max_step_db=0.2,
                   events=[dict(id='e', ue_imsi=1, start_s=1, end_s=1.5)])
        engine = Evasion(model, cfg)
        _, active = engine.transform(first)
        self.assertTrue(any(abs(r['delta_sinr_db']) > 0 for r in active))
        for row in active:
            self.assertLessEqual(abs(row['delta_sinr_db'] - row['previous_delta_db']), 0.2 + 1e-9)
        _, inactive = engine.transform(second)
        self.assertTrue(all(r['event_active'] == 0 and r['delta_sinr_db'] == 0 for r in inactive))
        self.assertTrue(any(abs(r['previous_delta_db']) > 0 for r in inactive))
        # Event turn-off deliberately resets the current delta to zero; the
        # active-event slew interval does not constrain this inactive row.
        self.assertTrue(all(r['bias_lower_db'] == r['bias_upper_db'] == 0 for r in inactive))

    def test_invalid_configurations(self):
        base = dict(mode='pgd', epsilon_db=1, events=[])
        invalid = [dict(base, access='all_cells'), dict(base, steps=0),
                   dict(base, steps=1.5), dict(base, restarts=101),
                   dict(base, step_size_db=float('nan')),
                   dict(base, max_step_db=math.inf), dict(base, max_step_db=-0.1)]
        for config in invalid:
            with self.subTest(config=config), self.assertRaises((ValueError, TypeError)):
                validate(config)


if __name__ == '__main__':
    unittest.main()
