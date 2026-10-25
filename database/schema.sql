CREATE SCHEMA IF NOT EXISTS ran_lab;
CREATE TABLE IF NOT EXISTS ran_lab.runs (
  run_id text PRIMARY KEY,
  dataset_sha256 text NOT NULL,
  plot_origin timestamptz NOT NULL DEFAULT clock_timestamp(),
  imported_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
COMMENT ON COLUMN ran_lab.runs.plot_origin IS
'Grafana display anchor only; not a measurement of wall-clock simulation start.';
CREATE TABLE IF NOT EXISTS ran_lab.application_windows (
  run_id text NOT NULL REFERENCES ran_lab.runs(run_id),
  window_start_s double precision NOT NULL,
  window_end_s double precision NOT NULL,
  ue_imsi bigint NOT NULL,
  traffic_profile text NOT NULL,
  direction text NOT NULL CHECK(direction IN ('DL','UL')),
  rx_bytes bigint NOT NULL CHECK(rx_bytes >= 0),
  app_goodput_mbps double precision NOT NULL CHECK(app_goodput_mbps >= 0),
  is_warmup boolean NOT NULL,
  attack_present boolean NOT NULL,
  attack_type text NOT NULL,
  record jsonb NOT NULL,
  PRIMARY KEY(run_id,window_start_s,ue_imsi),
  CHECK(window_end_s > window_start_s)
);
CREATE OR REPLACE VIEW ran_lab.application_timeseries AS
SELECT r.plot_origin + w.window_end_s * interval '1 second' AS time,
       w.* FROM ran_lab.application_windows w JOIN ran_lab.runs r USING(run_id);
