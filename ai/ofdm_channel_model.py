"""Differentiable LS-interpolation plus two-hidden-layer channel estimator.

Only received IQ is attackable. The fixed pilot/interpolation matrix is known
receiver preprocessing; train-only mean/scale and learned weights are saved.
"""
import numpy as np
from datasets.generate_rf_research import ls_interpolate


class ChannelModel:
    def __init__(self,x,pilots,seed):
        d=x.shape[1];eye=np.eye(d);basis=eye[:,0::2]+1j*eye[:,1::2]
        z=ls_interpolate(basis,pilots[:,0]+1j*pilots[:,1])
        self.transform=np.stack((z.real,z.imag),-1).reshape(d,d)
        f=x@self.transform;self.mean=f.mean(0);self.scale=np.maximum(f.std(0),1e-4)
        rng=np.random.default_rng(seed);self.parameters=[]
        dimensions=(d,64,64,d)
        for i in range(3):
            self.parameters += [rng.normal(0,np.sqrt(1/dimensions[i]),(dimensions[i],dimensions[i+1])),np.zeros(dimensions[i+1])]

    def forward(self,x):
        z=(x@self.transform-self.mean)/self.scale;w1,b1,w2,b2,w3,b3=self.parameters
        a=np.tanh(z@w1+b1);b=np.tanh(a@w2+b2)
        return b@w3+b3,(z,a,b)

    def loss_gradient(self,x,y,regression=True):
        assert regression
        out,(z,a,b)=self.forward(x);residual=out-y;loss=(residual**2).mean(1);g=2*residual/out.shape[1]
        w1,_,w2,_,w3,_=self.parameters
        gb=(g@w3.T)*(1-b*b);ga=(gb@w2.T)*(1-a*a)
        gx=((ga@w1.T)/self.scale)@self.transform.T;n=len(x)
        return loss,gx,[z.T@ga/n,ga.mean(0),a.T@gb/n,gb.mean(0),b.T@g/n,g.mean(0)]

    def save(self,path):
        np.savez_compressed(path,transform=self.transform,mean=self.mean,scale=self.scale,
                            **{'p'+str(i):v for i,v in enumerate(self.parameters)})

    @classmethod
    def load(cls,path):
        model=cls.__new__(cls)
        with np.load(path) as a:
            for k in ['transform','mean','scale']:setattr(model,k,a[k].copy())
            model.parameters=[a['p'+str(i)].copy() for i in range(6)]
        return model


def fit(model,x,y,vx,vy,regression,seed,epochs=60):
    rng=np.random.default_rng(seed);m=[np.zeros_like(p) for p in model.parameters];v=[p.copy() for p in m]
    best=None;bestloss=float('inf');t=0;selected=0
    for epoch in range(epochs):
        order=rng.permutation(len(x))
        for start in range(0,len(x),128):
            ids=order[start:start+128];g=model.loss_gradient(x[ids],y[ids],regression)[2];t+=1
            for i in range(6):
                grad=np.clip(g[i],-10,10);m[i]=.9*m[i]+.1*grad;v[i]=.999*v[i]+.001*grad*grad
                model.parameters[i]-=.003*(m[i]/(1-.9**t))/(np.sqrt(v[i]/(1-.999**t))+1e-8)
        loss=float(model.loss_gradient(vx,vy,regression)[0].mean())
        if loss<bestloss:bestloss=loss;best=[p.copy() for p in model.parameters];selected=epoch+1
    model.parameters=best
    return dict(selected_epoch=selected,validation_loss=bestloss,epochs=epochs)
