"""Coverage and policy tests for one-step robust forecast certificates."""
import copy
import unittest

import numpy as np

from ai.model import FEATURES, Forecaster
from ai.policy import recommendations
from ai.robust import forecast_interval


def model_with(weights=None, bias=0.0, limit=6.0):
    x = np.zeros((20, len(FEATURES)))
    model = Forecaster.fit(x, np.zeros(20), np.zeros(20))
    p = model.parameters
    p['mean'] = [0.0] * len(FEATURES)
    p['median'] = [0.0] * len(FEATURES)
    p['scale'] = [1.0] * len(FEATURES)
    p['weights'] = list(weights or [0.0] * len(FEATURES))
    p['bias'] = bias
    p['max_forecast_change_db'] = limit
    return model


def observation(current=5.0):
    return dict(run_id='r', ue=4, cell=1, tick=100, decision_time_s=10.1,
                current=current, features=[current, current, 0.5, 0.2, 0.0, 2.0, 0.1, 0.0],
                warmup=False, current_path_cell=1)


class ForecastIntervalTests(unittest.TestCase):
    def test_interval_covers_dense_independent_bias_grid_and_clean_score(self):
        cases = [
            ([-1.4, 0.0, 0, 0.1, 0, 0, 0, 0], 0.0, 6.0),  # negative total slope
            ([0.3, -0.2, 0, 1.1, 0, 0, 0, 0], 0.0, 6.0),  # previous-bias dependence
            ([1.1, 0.2, 0, 0.5, 0, 0, 0, 0], 5.5, 6.0),  # clipping saturation
        ]
        budget = 1.25
        grid = np.linspace(-budget, budget, 201)
        for weights, bias, limit in cases:
            with self.subTest(weights=weights, bias=bias):
                model = model_with(weights, bias, limit)
                item = observation()
                low, high = forecast_interval(model, item, budget)
                clean = float(model.predict([item['features']], [item['current']])[0])
                self.assertLessEqual(low, clean + 1e-10)
                self.assertGreaterEqual(high, clean - 1e-10)
                for previous in grid:
                    scores = model.predict(
                        [[item['features'][0] + delta,
                          item['features'][1] + delta,
                          *item['features'][2:3],
                          item['features'][3] + delta - previous,
                          *item['features'][4:]]
                         for delta in grid],
                        [item['current'] + delta for delta in grid])
                    self.assertGreaterEqual(min(scores), low - 1e-9)
                    self.assertLessEqual(max(scores), high + 1e-9)

    def test_interval_does_not_depend_on_trajectory_history_metadata(self):
        model = model_with([0.2, 0.1, 0, 0.4, 0, 0, 0, 0])
        item = observation()
        first = forecast_interval(model, item, 0.8)
        item_with_history = copy.deepcopy(item)
        item_with_history['previous_delta_db'] = 0.75
        second = forecast_interval(model, item_with_history, 0.8)
        self.assertEqual(first, second)

    def test_invalid_budgets_are_rejected(self):
        model = model_with()
        for budget in (-0.01, 5.01, float('nan'), float('inf'), '-1'):
            with self.subTest(budget=budget), self.assertRaises(ValueError):
                forecast_interval(model, observation(), budget)


def cells(candidate_current, path_cell=1):
    return [dict(run_id='r', ue=4, cell=1, tick=100, decision_time_s=10.1,
                 current=0.0, features=[0.0] * len(FEATURES), warmup=False,
                 current_path_cell=path_cell),
            dict(run_id='r', ue=4, cell=2, tick=100, decision_time_s=10.1,
                 current=candidate_current, features=[0.0] * len(FEATURES), warmup=False,
                 current_path_cell=path_cell)]


class RobustPolicyTests(unittest.TestCase):
    def setUp(self):
        self.model = model_with()

    def test_zero_budget_matches_nonrobust_action(self):
        observations = cells(4.0)
        ordinary, _ = recommendations(self.model, observations, hysteresis_db=3.0)
        zero_robust, _ = recommendations(self.model, observations, hysteresis_db=3.0,
                                         robust_budget_db=0.0)
        self.assertEqual([r['action'] for r in zero_robust], [r['action'] for r in ordinary])
        self.assertEqual(zero_robust[0]['action'], 'recommend_handover')

    def test_uncertain_gain_holds_while_clean_gain_recommends(self):
        observations = cells(4.0)
        clean, _ = recommendations(self.model, observations, hysteresis_db=3.0)
        robust, _ = recommendations(self.model, observations, hysteresis_db=3.0,
                                     robust_budget_db=1.0)
        self.assertEqual(clean[0]['action'], 'recommend_handover')
        self.assertEqual(robust[0]['action'], 'hold')
        self.assertEqual(robust[0]['reason'], 'uncertified_gain')

    def test_large_certified_gain_can_recommend(self):
        robust, _ = recommendations(self.model, cells(10.0), hysteresis_db=3.0,
                                     robust_budget_db=1.0)
        self.assertEqual(robust[0]['action'], 'recommend_handover')
        self.assertGreaterEqual(robust[0]['certified_gain_lower_db'], 3.0)

    def test_same_cell_is_never_a_handover_recommendation(self):
        result, _ = recommendations(self.model, cells(10.0, path_cell=2), hysteresis_db=0.0,
                                    robust_budget_db=1.0)
        self.assertNotEqual(result[0]['action'], 'recommend_handover')

    def test_invalid_robust_budget_is_rejected_by_policy(self):
        for budget in (-1, 6, float('nan')):
            with self.subTest(budget=budget), self.assertRaises(ValueError):
                recommendations(self.model, cells(10.0), robust_budget_db=budget)


if __name__ == '__main__':
    unittest.main()
