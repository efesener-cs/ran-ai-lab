"""Recommendations only: no E2 RC messages, control-file writes or RAN changes."""


def recommendations(model,observations,hysteresis_db=3.0,cooldown_s=0.5,state=None):
    groups={}
    cells_by_run={}
    for o in observations:
        cells_by_run.setdefault(o['run_id'],set()).add(o['cell'])
        if not o['warmup']:groups.setdefault((o['run_id'],o['ue'],o['tick']),[]).append(o)
    proposals=[];scores=[];last_proposal=state if state is not None else {}
    for key,items in sorted(groups.items(),key=lambda pair:(pair[0][0],pair[0][2],pair[0][1])):
        run,ue,tick=key
        items=sorted(items,key=lambda o:o['cell'])
        if {o['cell'] for o in items}!=cells_by_run[run]:continue
        prediction=model.predict([o['features'] for o in items],[o['current'] for o in items])
        best_index=max(range(len(prediction)),key=lambda i:prediction[i]);best=items[best_index]
        current_path=items[0]['current_path_cell'];now=best['decision_time_s']
        current_index=next((i for i,o in enumerate(items) if o['cell']==current_path),None)
        gain=float(prediction[best_index]-prediction[current_index]) if current_index is not None else None
        action='hold';reason='hysteresis_or_same_cell'
        if current_index is None:
            action='observe';reason='no_observed_NR_path'
        elif best['cell']!=current_path and gain>=hysteresis_db:
            if now-last_proposal.get((run,ue),-1e9)>=cooldown_s-1e-8:
                action='recommend_handover';reason='predicted_SINR_gain'
                last_proposal[run,ue]=now
            else:reason='recommendation_cooldown'
        proposals.append(dict(run_id=run,decision_time_s=now,ue_imsi=ue,
            observed_path_cell_id=current_path if current_path is not None else '',
            recommended_cell_id=best['cell'],action=action,reason=reason,
            predicted_best_sinr_db=float(prediction[best_index]),
            predicted_gain_db=gain if gain is not None else '',network_action_applied=0))
        for o,value in zip(items,prediction):
            scores.append(dict(run_id=run,decision_time_s=now,ue_imsi=ue,nr_cell_id=o['cell'],
                observed_sinr_mean_db=o['current'],predicted_next_sinr_db=float(value)))
    return proposals,scores
