"""Differentiable IQ moments, NumPy MLP, and receiver-input RF attacks.

The classifier is a two-hidden-layer neural network on fixed IQ moments.
Attacks differentiate through the moments into raw interleaved IQ samples.
"""
import numpy as np


def features(x):
    iq = x.reshape(len(x), -1, 2)
    i, q = iq[:, :, 0], iq[:, :, 1]
    return np.column_stack((i.mean(1), q.mean(1), (i*i).mean(1),
                            (q*q).mean(1), (i**4).mean(1),
                            (q**4).mean(1), (i*q).mean(1)))


def feature_backward(x, gradient):
    iq = x.reshape(len(x), -1, 2)
    i, q = iq[:, :, 0], iq[:, :, 1]
    g = gradient
    result = np.empty_like(iq)
    result[:, :, 0] = (g[:, 0, None] + 2*i*g[:, 2, None]
                       + 4*i**3*g[:, 4, None] + q*g[:, 6, None]) / i.shape[1]
    result[:, :, 1] = (g[:, 1, None] + 2*q*g[:, 3, None]
                       + 4*q**3*g[:, 5, None] + i*g[:, 6, None]) / i.shape[1]
    return result.reshape(x.shape)


class RFModel:
    def __init__(self, x, outputs, seed):
        f = features(x)
        self.mean = f.mean(0)
        self.scale = np.maximum(f.std(0), 1e-4)
        rng = np.random.default_rng(seed)
        self.parameters = []
        dimensions = (7, 32, 32, outputs)
        for n in range(3):
            self.parameters.append(rng.normal(0, np.sqrt(1 / dimensions[n]),
                                              (dimensions[n], dimensions[n+1])))
            self.parameters.append(np.zeros(dimensions[n+1]))

    def forward(self, x):
        z = (features(x) - self.mean) / self.scale
        w1, b1, w2, b2, w3, b3 = self.parameters
        a = np.tanh(z @ w1 + b1)
        b = np.tanh(a @ w2 + b2)
        return b @ w3 + b3, (z, a, b)

    def loss_gradient(self, x, y, regression=False):
        out, (z, a, b) = self.forward(x)
        if regression:
            residual = out - y
            losses = (residual**2).mean(1)
            g = 2 * residual / out.shape[1]
        else:
            shifted = out - out.max(1, keepdims=True)
            exp = np.exp(shifted)
            probabilities = exp / exp.sum(1, keepdims=True)
            indices = np.arange(len(x))
            losses = np.log(exp.sum(1)) - shifted[indices, y]
            g = probabilities.copy()
            g[indices, y] -= 1
        w1, _, w2, _, w3, _ = self.parameters
        gb = (g @ w3.T) * (1 - b*b)
        ga = (gb @ w2.T) * (1 - a*a)
        gf = (ga @ w1.T) / self.scale
        count = len(x)
        weight_gradients = [z.T @ ga / count, ga.mean(0), a.T @ gb / count,
                            gb.mean(0), b.T @ g / count, g.mean(0)]
        return losses, feature_backward(x, gf), weight_gradients

    def save(self, path):
        values = dict(mean=self.mean, scale=self.scale)
        for index, parameter in enumerate(self.parameters):
            values['p' + str(index)] = parameter
        np.savez_compressed(path, **values)

    @classmethod
    def load(cls, path):
        model = cls.__new__(cls)
        with np.load(path, allow_pickle=False) as archive:
            model.mean = archive['mean'].copy()
            model.scale = archive['scale'].copy()
            model.parameters = []
            for index in range(6):
                model.parameters.append(archive['p' + str(index)].copy())
        return model


def train(x, y, vx, vy, regression, seed, epochs):
    outputs = 2
    if not regression:
        outputs = int(y.max()) + 1
    model = RFModel(x, outputs, seed)
    rng = np.random.default_rng(seed)
    first, second = [], []
    for p in model.parameters:
        first.append(np.zeros_like(p))
        second.append(np.zeros_like(p))
    step = 0
    best_loss = float('inf')
    best = None
    best_epoch = 0
    for epoch in range(epochs):
        order = rng.permutation(len(x))
        for start in range(0, len(x), 128):
            index = order[start:start+128]
            _, _, gradients = model.loss_gradient(x[index], y[index], regression)
            step += 1
            for k in range(len(gradients)):
                first[k] = .9 * first[k] + .1 * gradients[k]
                second[k] = .999 * second[k] + .001 * gradients[k]**2
                model.parameters[k] -= .003 * (first[k] / (1-.9**step)) / (
                    np.sqrt(second[k] / (1-.999**step)) + 1e-8)
        loss = float(model.loss_gradient(vx, vy, regression)[0].mean())
        if loss < best_loss:
            best_loss = loss
            best = []
            for p in model.parameters:
                best.append(p.copy())
            best_epoch = epoch + 1
    model.parameters = best
    return model, dict(validation_loss=best_loss, selected_epoch=best_epoch)


def normalize(x):
    return x / np.maximum(np.linalg.norm(x, axis=1, keepdims=True), 1e-30)


def project(delta, radius):
    norms = np.linalg.norm(delta, axis=1, keepdims=True)
    return delta * np.minimum(1, radius / np.maximum(norms, 1e-30))


def attack(model, x, target, mode, ratio, regression, seed, steps=30):
    """Per-frame L2 budget: ||delta||² <= ratio * ||clean received IQ||².

    Targeted classification minimizes target CE. Regression maximizes MSE.
    FGSM uses a nested Linf ball r/sqrt(d); PGD projects onto the L2 ball.
    PGD retains the best objective per frame, including the zero perturbation.
    """
    radius = np.sqrt(ratio) * np.linalg.norm(x, axis=1, keepdims=True)
    delta = np.zeros_like(x)
    if mode == 'none' or ratio == 0:
        return delta
    rng = np.random.default_rng(seed)
    if mode == 'random':
        return normalize(rng.normal(size=x.shape)) * radius
    direction = 1 if regression else -1
    if mode == 'fgsm':
        gradient = model.loss_gradient(x, target, regression)[1]
        return direction * np.sign(gradient) * radius / np.sqrt(x.shape[1])
    if mode != 'pgd':
        raise ValueError('Unknown RF attack: ' + mode)
    best = delta.copy()
    best_value = direction * model.loss_gradient(x, target, regression)[0]
    # Start at the clean frame as well as a random point; no test-based tuning.
    for restart in range(2):
        delta = np.zeros_like(x)
        if restart:
            delta = normalize(rng.normal(size=x.shape)) * radius * .5
        for _ in range(steps + 1):
            losses, gradient, _ = model.loss_gradient(x + delta, target, regression)
            value = direction * losses
            improved = value > best_value
            best[improved] = delta[improved]
            best_value[improved] = value[improved]
            delta = project(delta + direction * normalize(gradient) * radius * .15, radius)
    return best
