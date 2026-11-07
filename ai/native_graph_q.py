"""Small NumPy message-passing Q network for measured native LTE transitions.

Two cell nodes exchange one learned message; a joint Q head chooses hold/cell1/
cell2. This is a research reference, not a reproduction of a named DRL paper.
"""
import numpy as np


def encode(state):
    nodes = []
    for i in range(2):
        nodes.extend([state[f'cell{i}_load']/10, state[f'cell{i}_sinr_db']/20,
                      state[f'cell{i}_goodput_mbps']/20, float(state['target_cell'] == i+1)])
    return np.asarray(nodes + [state['target_sinr_db']/20,
                              state['target_goodput_mbps']/8, state['pending'], state.get('handover_budget_remaining', 2)/2], dtype=float)


class GraphQ:
    def __init__(self, seed):
        rng = np.random.default_rng(seed)
        self.w = dict(ws=rng.normal(0, .2, (4, 12)), wn=rng.normal(0, .2, (4, 12)),
                      b=np.zeros(12), wh=rng.normal(0, .15, (28, 24)), bh=np.zeros(24),
                      wo=rng.normal(0, .15, (24, 3)), bo=np.zeros(3))
        self.m = {k: np.zeros_like(v) for k,v in self.w.items()}
        self.v = {k: np.zeros_like(v) for k,v in self.w.items()}
        self.t = 0

    def forward(self, x, cache=False):
        x = np.atleast_2d(x)
        n = x[:, :8].reshape(-1, 2, 4)
        w = self.w
        h = np.tanh(n @ w['ws'] + n[:, ::-1] @ w['wn'] + w['b'])
        z = np.concatenate([h.reshape(-1, 24), x[:, 8:]], axis=1)
        a = np.tanh(z @ w['wh'] + w['bh'])
        q = a @ w['wo'] + w['bo']
        return (q, (n,h,z,a)) if cache else q

    def train(self, x, actions, targets, lr=.001):
        q, (n,h,z,a) = self.forward(x, True)
        err = q[np.arange(len(q)), actions] - targets
        dq = np.zeros_like(q)
        dq[np.arange(len(q)), actions] = np.clip(err, -1, 1)/len(q)
        w = self.w
        g = dict(wo=a.T @ dq, bo=dq.sum(0))
        da = (dq @ w['wo'].T)*(1-a*a)
        g.update(wh=z.T @ da, bh=da.sum(0))
        dh = (da @ w['wh'].T)[:, :24].reshape(-1,2,12)*(1-h*h)
        g.update(ws=np.einsum('bni,bnj->ij', n, dh),
                 wn=np.einsum('bni,bnj->ij', n[:, ::-1], dh), b=dh.sum((0,1)))
        self.t += 1
        for k in w:
            grad = np.clip(g[k], -5, 5)
            self.m[k] = .9*self.m[k]+.1*grad
            self.v[k] = .999*self.v[k]+.001*grad*grad
            w[k] -= lr*(self.m[k]/(1-.9**self.t))/(np.sqrt(self.v[k]/(1-.999**self.t))+1e-8)
        return float(np.mean(err*err))

    def save(self, path):
        np.savez(path, **self.w)

    @classmethod
    def load(cls, path):
        model = cls(0)
        with np.load(path) as data:
            model.w = {k: data[k].copy() for k in model.w}
        return model
