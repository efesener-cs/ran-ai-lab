import copy
import json
from pathlib import Path
import unittest
from ai.runtime import RuntimeForecaster


class RuntimeValidationTests(unittest.TestCase):
    def setUp(self):
        self.parameters = json.loads((Path(__file__).parent/'tests/fixtures/model.json').read_text())

    def test_invalid_scalars_rejected_before_inference(self):
        for name, value in [('bias', float('nan')), ('max_forecast_change_db', float('inf')),
                            ('max_forecast_change_db', -1)]:
            parameters = copy.deepcopy(self.parameters)
            parameters[name] = value
            with self.assertRaises(ValueError):
                RuntimeForecaster(parameters)

    def test_truncated_batch_and_missing_current_cannot_silently_predict(self):
        model = RuntimeForecaster(self.parameters)
        with self.assertRaises(ValueError):
            model.predict([[0]*8, [0]*8], [1])
        with self.assertRaises(ValueError):
            model.predict([[0]*8], [float('nan')])
