"""Parameter factories for simple forecasting baselines."""
from copy import deepcopy


def persistence_parameters(fitted_parameters):
    """Return a ridge-schema model that forecasts the current value unchanged."""
    parameters = deepcopy(fitted_parameters)
    if parameters.get('algorithm') != 'residual_ridge':
        raise ValueError('Persistence baseline requires residual_ridge parameters')
    features = parameters.get('features')
    if not isinstance(features, list) or not features:
        raise ValueError('Missing ridge feature schema')
    if len(parameters.get('weights', [])) != len(features):
        raise ValueError('Ridge weight schema mismatch')
    parameters['weights'] = [0.0] * len(features)
    parameters['bias'] = 0.0
    parameters['baseline'] = 'persistence'
    return parameters
