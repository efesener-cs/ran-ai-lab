"""Evidence and scoring for local training-data poisoning, not RAN control."""
import csv
import json
from pathlib import Path
import numpy as np

MODES = ('label_flip', 'feature_noise', 'backdoor')


def read_table(path, task):
    with Path(path).open(newline='') as handle:
        reader = csv.reader(handle)
        header = next(reader)
        if header[:5] != ['task','id','label','h_i','h_q'] or (len(header)-5)%2:
            raise ValueError('Training RF schema mismatch')
        length = (len(header)-5)//2
        expected = []
        for k in range(length): expected.extend(['i'+str(k),'q'+str(k)])
        if header[5:] != expected: raise ValueError('Training IQ header mismatch')
        x, y, ids = [], [], []
        for row in reader:
            if len(row) != len(header) or row[0] != task: raise ValueError('Invalid training RF row')
            if not np.isfinite(np.asarray(row[3:],dtype=float)).all(): raise ValueError('Nonfinite training RF truth/input')
            ids.append(int(row[1])); y.append(int(row[2])); x.append(np.asarray(row[5:],dtype=float))
    x, y, ids = np.asarray(x), np.asarray(y), np.asarray(ids)
    classes = 2 if task == 'sensing' else 3
    if not len(x) or len(set(ids.tolist())) != len(ids) or not np.isfinite(x).all() or np.any(y < 0) or np.any(y >= classes):
        raise ValueError('Invalid or duplicate training RF content')
    return x, y, ids


def extract_task(source, target, task):
    with Path(source).open(newline='') as src, Path(target).open('w',newline='') as out:
        reader, writer = csv.reader(src), csv.writer(out)
        writer.writerow(next(reader))
        for row in reader:
            if row[0] == task: writer.writerow(row)
    return read_table(target,task)


def verify_transform(source, transformed, task):
    x, y, ids = read_table(source,task)
    observed, labels, output_ids = read_table(transformed,task)
    if x.shape != observed.shape or not np.array_equal(ids,output_ids):
        raise ValueError('Training transform changed shape/identity')
    with Path(source).open(newline='') as a, Path(transformed).open(newline='') as b:
        for original, changed in zip(csv.DictReader(a),csv.DictReader(b)):
            if any(float(original[key])!=float(changed[key]) for key in ('h_i','h_q')):
                raise ValueError('Training transform changed H truth')
    meta = json.loads(Path(str(transformed)+'.meta.json').read_text())
    mode, target = meta['mode'], meta['target_class']
    with Path(str(transformed)+'.audit.csv').open(newline='') as handle:
        audit = list(csv.DictReader(handle))
    if len(audit) != len(x) or meta['rows'] != len(x) or meta['task'] != task:
        raise ValueError('Training audit coverage mismatch')
    selected = np.array([int(r['selected']) for r in audit])
    if np.any((selected != 0)&(selected != 1)): raise ValueError('Invalid selection flag')
    selected = selected.astype(bool)
    expected_count = int(np.floor(len(x)*meta['fraction_requested']+.5))
    if int(selected.sum()) != expected_count or meta['selected_rows'] != expected_count:
        raise ValueError('Training poison fraction mismatch')
    if not np.array_equal(x[~selected],observed[~selected]) or not np.array_equal(y[~selected],labels[~selected]):
        raise ValueError('Unselected training frames changed')
    relabel = mode in ('label_flip','backdoor')
    if relabel:
        if np.any(y[selected] == target) or np.any(labels[selected] != target):
            raise ValueError('Targeted poisoning label rule violated')
    elif not np.array_equal(y,labels): raise ValueError('Unexpected training/probe label change')
    delta = observed-x
    actual_energy = np.sum(delta*delta,axis=1)
    clean_energy = np.sum(x*x,axis=1)
    if mode in ('none','label_flip'):
        if np.any(delta != 0): raise ValueError('Label-only/zero transformation changed IQ')
    elif mode in ('backdoor','trigger_only'):
        expected = x.copy()
        length = meta['trigger_length_complex_samples']
        expected[selected,-2*length::2] += meta['trigger_amplitude_i']
        if not np.array_equal(expected,observed): raise ValueError('Trigger geometry/amplitude mismatch')
    elif mode == 'random_patch':
        if np.any(delta[:,:-2*meta['trigger_length_complex_samples']] != 0):
            raise ValueError('Random patch escaped trigger support')
    elif mode != 'feature_noise': raise ValueError('Unknown training transformation')
    if mode in ('feature_noise','random_patch'):
        desired = np.zeros(len(x))
        if mode == 'feature_noise': desired[selected] = clean_energy[selected]*10**(meta['noise_psr_db']/10)
        else: desired[selected] = meta['trigger_length_complex_samples']*meta['trigger_amplitude_i']**2
        if not np.allclose(actual_energy,desired,rtol=1e-10,atol=1e-12):
            raise ValueError('Training/probe energy mismatch')
    for k, row in enumerate(audit):
        if int(row['id']) != ids[k] or row['task'] != task or int(row['clean_label']) != y[k] or int(row['training_label']) != labels[k]:
            raise ValueError('Training audit truth/identity mismatch')
        if row['attack_type'] != (mode if selected[k] else 'none'):
            raise ValueError('Training audit type mismatch')
        patch = bool(selected[k] and mode in ('backdoor','trigger_only'))
        if int(row['trigger_present']) != int(patch): raise ValueError('Training audit trigger flag mismatch')
        ratio = actual_energy[k]/max(clean_energy[k],1e-30)
        for key,value in (('clean_energy',clean_energy[k]),('delta_energy',actual_energy[k]),('actual_power_ratio',ratio)):
            if not np.isclose(float(row[key]),value,rtol=1e-10,atol=1e-12):
                raise ValueError('Training audit energy mismatch')
    return dict(rows=len(x),selected=int(selected.sum()),fraction=expected_count/len(x),
                selected_ids=ids[selected].tolist())


def classification(y, prediction, classes):
    confusion = np.zeros((classes,classes),dtype=int)
    for actual, predicted in zip(y,prediction): confusion[int(actual),int(predicted)] += 1
    f1=[]
    for k in range(classes):
        tp=int(confusion[k,k]); denominator=int(confusion[k,:].sum()+confusion[:,k].sum())
        f1.append(2*tp/denominator if denominator else 0.)
    return dict(accuracy=float(np.mean(y==prediction)),macro_f1=float(np.mean(f1)),confusion=confusion.tolist())


def evaluate(model, reference, clean, triggered, random_control, truth, target):
    base = reference.forward(clean)[0].argmax(1)
    reference_triggered = reference.forward(triggered)[0].argmax(1)
    clean_prediction = model.forward(clean)[0].argmax(1)
    triggered_prediction = model.forward(triggered)[0].argmax(1)
    random_prediction = model.forward(random_control)[0].argmax(1)
    eligible = (base == truth)&(truth != target)
    paired = eligible&(clean_prediction == truth)
    def rate(prediction,mask):
        n=int(mask.sum()); hits=int(np.sum(mask&(prediction==target)))
        return dict(eligible=n,hits=hits,rate=hits/n if n else None)
    metrics=dict(clean=classification(truth,clean_prediction,int(truth.max())+1),
                 clean_reference=classification(truth,base,int(truth.max())+1),
                 targeted_clean_errors=rate(clean_prediction,eligible),
                 triggered_target_hits=rate(triggered_prediction,eligible),
                 reference_triggered_target_hits=rate(reference_triggered,eligible),
                 random_patch_target_hits=rate(random_prediction,eligible),
                 conditional_backdoor_asr=rate(triggered_prediction,paired))
    predictions=dict(reference_clean=base,model_clean=clean_prediction,
                     model_triggered=triggered_prediction,model_random_patch=random_prediction)
    return metrics,predictions
