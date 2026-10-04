CREATE TABLE indicator_versions(version text PRIMARY KEY, body jsonb NOT NULL, created_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
ALTER TABLE runs ADD COLUMN indicator_version text REFERENCES indicator_versions;
CREATE TABLE suppressions(suppression_id text PRIMARY KEY, scope_id text NOT NULL REFERENCES runs(scope_id), body jsonb NOT NULL, audited_at timestamptz NOT NULL DEFAULT now(), validity_mode text NOT NULL CHECK(validity_mode IN ('scenario_interval','from_now')));
CREATE INDEX suppression_scope ON suppressions(scope_id);
CREATE TABLE indicator_matches(event_id text REFERENCES events, version text REFERENCES indicator_versions, kind text NOT NULL, value text NOT NULL, description text NOT NULL, PRIMARY KEY(event_id,version,kind,value));
CREATE TABLE event_exclusions(event_id text PRIMARY KEY REFERENCES events, reason text NOT NULL, watermark_us bigint NOT NULL);
CREATE INDEX alerts_scope_filters ON alerts(run_id, (body->>'detector_id'), (body->>'status'));
CREATE TABLE alert_windows(alert_id text REFERENCES alerts ON DELETE CASCADE, window_end_us bigint NOT NULL, window_start_us bigint NOT NULL, observed jsonb NOT NULL, PRIMARY KEY(alert_id,window_end_us));
