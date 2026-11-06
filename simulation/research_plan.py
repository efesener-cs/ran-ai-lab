"""Preregistered synthetic collection matrix; unchanged role groups across modes."""
from itertools import zip_longest

FAMILIES=('udp_flood','udp_ddos','pulsed_udp','udp_port_scan','tcp_connection_churn','icmp_flood','mixed')


def collection_recipes():
    partition={'train':list(range(1510001,1510025)), 'validation':list(range(1520001,1520013)),
               'test':list(range(1530001,1530025)), 'ood':list(range(1540001,1540017))}
    ip=[];rf=[];attacks=[]
    for role,seeds in partition.items():
        for index,seed in enumerate(seeds):
            for mode in ('none',*FAMILIES):
                for regime in (('overlap',) if mode=='none' else ('low','overlap','high')):
                    ip.append(dict(id=f'ip-{role}-{seed}-{mode}-{regime}',kind='ip',phase='collection',capacity=4,
                        role=role,seed=seed,attack=mode,environment='ood_network' if role=='ood' else 'id',
                        regime=regime,sim_time=190,warmup=10,pcap_audit=(role=='train' and index==0 and mode in ('none','mixed') and regime=='overlap')))
            for task in ('sensing','amc','channel'):
                rf.append(dict(id=f'rf-{task}-{role}-{seed}',kind='rf',phase='collection',capacity=4,
                    role=role,seed=seed+1000000,task=task,samples=2000,split=role,
                    generator_args=['--snr-min=-12','--snr-max=12','--cfo-max=.006','--timing-max=.45','--taps=6','--noise-uncertainty-db=4'] if role=='ood' else []))
    for repeat in range(5):
        for profile,snr in (('diverse',10),('stress',0)):
            parent=f'rf-reference-{profile}-r{repeat}'
            attacks.append(dict(id=parent,kind='rf_attack',phase='collection',capacity=4,role='reference',
                profile=profile,snr_db=snr,seeds=[1610001+repeat,1620001+repeat,1630001+repeat],
                scientific_scope='Separate 3-class moment-MLP reference, receiver-additive FGSM/PGD; not new six-class victim or OTA'))
            if profile=='diverse':
                attacks.append(dict(id=f'training-integrity-r{repeat}',kind='training_attack',phase='collection',capacity=4,
                    role='reference',parent=parent,depends=[parent],attack_seed=1640001+repeat,
                    scientific_scope='Local label flip/random feature corruption/static IQ trigger; not DRL SleeperNets/TrojDRL or federated poisoning'))
    jobs=[]
    # Interleave domains so offline progress is not restricted to one long track.
    for group in zip_longest([ip[i:i+8] for i in range(0,len(ip),8)],rf,attacks):
        block,radio,attack=group
        if block:jobs.extend(block)
        if radio:jobs.append(radio)
        if attack:jobs.append(attack)
    for j in jobs:j.update(state='pending',attempts=[])
    return jobs,partition
