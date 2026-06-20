-- Distributed login rate-limit state, shared across API replicas.
--
-- The in-memory LoginLimiter is per-process, so N replicas multiply every
-- budget by N. On Postgres the limiter records each attempt here instead and
-- counts within the sliding window, so the cap is enforced cluster-wide. One
-- row per recorded attempt; the (bucket_key, attempted_at) index keeps the
-- per-key window count and purge cheap.
CREATE TABLE login_attempts (
    bucket_key   TEXT        NOT NULL,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX login_attempts_key_time ON login_attempts (bucket_key, attempted_at);
