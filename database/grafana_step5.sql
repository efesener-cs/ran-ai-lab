-- Enriched application CSV imports produced by analyze_experiments.py.
-- All queries group runs separately. Simulation time is not UTC measurement time.

-- Table panel: measured aggregate goodput by simulation window.
SELECT run_id, record->>'backend' AS backend,
       record->>'experiment_condition' AS condition,
       window_end_s AS simulation_time_s,
       sum(app_goodput_mbps) AS aggregate_goodput_mbps
FROM ran_lab.application_windows
WHERE NOT is_warmup AND record ? 'experiment_condition'
GROUP BY run_id, record->>'backend', record->>'experiment_condition',window_end_s
ORDER BY run_id,window_end_s;

-- Table/bar panel: totals, no sum across distinct experimental runs.
SELECT run_id, record->>'experiment_condition' AS condition,
       sum(rx_bytes) AS rx_bytes,
       sum((record->>'aml_event_active')::integer) AS active_ue_windows,
       sum((record->>'aml_input_perturbed')::integer) AS affected_ue_windows
FROM ran_lab.application_windows
WHERE NOT is_warmup AND record ? 'experiment_condition'
GROUP BY run_id, record->>'experiment_condition'
ORDER BY run_id;

-- Optional time-series panel using a display anchor (not real capture time).
-- Set Grafana's time range to cover ran_lab.runs.plot_origin.
SELECT r.plot_origin + w.window_end_s * interval '1 second' AS "time",
       w.run_id AS metric, sum(w.app_goodput_mbps) AS value
FROM ran_lab.application_windows w JOIN ran_lab.runs r USING(run_id)
WHERE NOT w.is_warmup AND w.record ? 'experiment_condition'
GROUP BY r.plot_origin,w.window_end_s,w.run_id
ORDER BY "time";
