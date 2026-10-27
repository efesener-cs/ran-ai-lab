"""Tests for model-compatible persistence baseline parameters."""
import tempfile
import unittest
from pathlib import Path

import numpy as np

from ai.baselines import persistence_parameters
from ai.evasion import Evasion
from ai.model import FEATURES, Forecaster
from ai.runtime import RuntimeForecaster


def fitted_model():
    x = np.arange(20 * len(FEATURES), dtype=float).reshape(20, len(FEATURES))
    current = np.linspace(0, 10, 20)
    target = current + np.linspace(-1, 1, 20)
    return Forecaster.fit(x, target, current)


class PersistenceBaselineTests(unittest.TestCase):
    def test_preserves_model_schema_and_does_not_mutate_input(self):
        fitted = fitted_model()
        original = {key: list(value) if isinstance(value, list) else value
                    for key, value in fitted.parameters.items()}
        params = persistence_parameters(fitted.parameters)
        self.assertEqual(params['features'], FEATURES)
        self.assertEqual(params['algorithm'], 'residual_ridge')
        self.assertEqual(params['baseline'], 'persistence')
        self.assertEqual(params['weights'], [0.0] * len(FEATURES))
        self.assertEqual(params['bias'], 0.0)
        self.assertEqual(fitted.parameters, original)
        self.assertIsNot(params['mean'], fitted.parameters['mean'])

    def test_prediction_is_current_even_when_features_contain_nan(self):
        model = Forecaster(persistence_parameters(fitted_model().parameters))
        prediction = model.predict([[float('nan')] * len(FEATURES), [999] * len(FEATURES)], [3.25, -2])
        np.testing.assert_array_equal(prediction, [3.25, -2])

    def test_attack_changes_persistence_forecast_only_through_current_sinr(self):
        model = Forecaster(persistence_parameters(fitted_model().parameters))
        observations = [dict(run_id='r', ue=7, cell=1, tick=10, decision_time_s=1.1,
                             current=10.0, features=[10.0] * len(FEATURES), warmup=False),
                        dict(run_id='r', ue=7, cell=2, tick=10, decision_time_s=1.1,
                             current=9.0, features=[9.0] * len(FEATURES), warmup=False)]
        config = {'mode': 'bias', 'epsilon_db': 1.0, 'access': 'two_cell',
                  'events': [{'id': 'e', 'ue_imsi': 7, 'start_s': 1.0, 'end_s': 2.0}]}
        changed, _ = Evasion(model, config).transform(observations)
        predicted = model.predict([o['features'] for o in changed], [o['current'] for o in changed])
        self.assertEqual([round(v - o['current'], 7) for v, o in zip(predicted, observations)], [-1.0, 1.0])
        self.assertEqual([round(o['current'], 7) for o in changed], [9.0, 10.0])

    def test_saved_model_loads_in_numpy_and_runtime_inference(self):
        params = persistence_parameters(fitted_model().parameters)
        model = Forecaster(params)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'persistence.json'
            model.save(path)
            loaded = Forecaster.load(path)
            runtime = RuntimeForecaster.load(path)
        x = [[float('nan')] * len(FEATURES)]
        np.testing.assert_array_equal(loaded.predict(x, [4.5]), [4.5])
        self.assertEqual(runtime.predict(x, [4.5]), [4.5])


if __name__ == '__main__':
    unittest.main()
