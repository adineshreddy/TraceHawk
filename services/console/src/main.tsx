import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";
type Session = { username: string; role: string; csrf_token: string };
type Run = {
  run_id: string;
  scope_id: string;
  scenario_id: string;
  status: string;
  processed_records: number;
  total_records: number;
  rule_version: string;
  indicator_version: string | null;
};
type Alert = {
  alert_id: string;
  source_ip: string;
  destination_ip: string | null;
  detector_id: string;
  severity: string;
  status: string;
  suppressed: boolean;
  suppression_id: string | null;
  explanation: string;
  rule_version: string;
  indicator_version: string | null;
  evidence_total_count: number;
  evidence_truncated: boolean;
  first_event_time_us: number;
  last_event_time_us: number;
  observed: Record<string, number>;
  thresholds: Record<string, string | number>;
};
type Event = {
  event_id: string;
  event_time_us: number;
  source_ip: string;
  destination_ip: string;
  source_port: number;
  destination_port: number;
  event_kind: string;
  time_basis: string;
  connection: { state: string | null; duration_us: number | null } | null;
  dns: {
    query: string | null;
    rcode: number | null;
    rcode_name: string | null;
  } | null;
  provenance: { zeek_version: string; capture_id: string };
};
type TimelineBin = { start_us: number; event_count: number };
type Suppression = {
  suppression_id: string;
  detector_id: string;
  source_ip: string;
  destination_ip: string | null;
  reason: string;
  created_by: string;
  created_at_us: number;
  expires_at_us: number;
};
type Evidence = {
  items: Event[];
  history: {
    actor: string;
    action: string;
    created_at: string;
    details: Record<string, unknown>;
  }[];
  timeline: TimelineBin[];
  event_eligibility: {
    event_id: string;
    eligible_for_temporal_rules: boolean;
    exclusion_reason: string | null;
  }[];
  matched_windows: {
    window_start_us: number;
    window_end_us: number;
    observed: Record<string, number>;
  }[];
  indicator_matches: {
    event_id: string;
    version: string;
    kind: string;
    value: string;
    description: string;
  }[];
  suppression: Suppression | null;
};
type Rule = {
  version: string;
  known_indicator: { enabled: boolean; indicator_version: string };
  [key: string]: unknown;
};
type Indicator = {
  version: string;
  provenance: string;
  entries: { kind: string; value: string; description: string }[];
};
type Host = {
  address: string;
  event_count: number;
  inbound: number;
  outbound: number;
  alert_count: number;
};
type HostDetail = {
  address: string;
  event_count: number;
  coverage: Record<string, number>;
  timeline: TimelineBin[];
  alerts: Alert[];
};
type EventItem = {
  event: Event;
  eligible_for_temporal_rules: boolean;
  exclusion_reason: string | null;
};
const detectors: Record<string, string> = {
  vertical_tcp_scan: "Possible vertical port scan",
  failed_tcp_connections: "Repeated failed TCP connections",
  dns_nxdomain_burst: "DNS NXDOMAIN burst",
  known_indicator: "Exact indicator match",
};
const when = (t: number) =>
  new Date(t / 1000).toISOString().replace("T", " ").replace("Z", " UTC");
function App() {
  const [session, setSession] = useState<Session | null>(null),
    [ready, setReady] = useState(false),
    [username, setUsername] = useState("operator"),
    [password, setPassword] = useState("");
  const [grafanaUrl, setGrafanaUrl] = useState<string | null>(null);
  const [page, setPage] = useState("Overview"),
    [runs, setRuns] = useState<Run[]>([]),
    [selected, setSelected] = useState(""),
    [overview, setOverview] = useState<{
      event_count: number;
      open_alert_count: number;
      suppressed_alert_count: number;
      pipeline_status: string;
    } | null>(null);
  const [evaluation, setEvaluation] = useState<{
    scope: string;
    captures: number;
    held_out_captures: number;
    benign_alerts: number;
    suppressed_alerts: number;
    rules: {
      family: string;
      tp: number;
      fp: number;
      fn: number;
      precision: number | null;
      recall: number | null;
      implemented: boolean;
    }[];
    model: {
      default_enabled: boolean;
      recommendation: string;
      new_true_positive_captures: string[];
    };
    short_trials: {
      workers: number;
      sources: number;
      mean_durable_events_per_s: number;
      max_p95_durable_observation_s: number;
    }[];
    engineering_target: {
      rate: number;
      seconds: number;
      completed: boolean;
      early_stop_reason: string | null;
      actually_published_s: number;
    };
    recovery_final_effect_parity: boolean;
  } | null>(null);
  const [ops, setOps] = useState<{
    status: string;
    workers: { component: string; status: string; fresh: boolean }[];
    partitions: {
      partition: number;
      next_offset: number;
      ownership_epoch: number;
      owner_id: string | null;
      lag: number;
      fresh: boolean | null;
    }[];
    queues: {
      pending_alert_updates: number;
      pending_deadletters: number;
      unreviewed_deadletters: number;
    };
  } | null>(null);
  const [quarantine, setQuarantine] = useState<
    {
      partition: number;
      broker_offset: number;
      reason: string;
      record_bytes: number | null;
      reviewed_at: string | null;
      delivered_at: string | null;
    }[]
  >([]);
  const [reviewReason, setReviewReason] = useState("");
  const [sourceDraft, setSourceDraft] = useState("");
  const [alerts, setAlerts] = useState<Alert[]>([]),
    [cursor, setCursor] = useState(""),
    [nextCursor, setNextCursor] = useState<string | null>(null),
    [filters, setFilters] = useState({
      detector_id: "",
      severity: "",
      status: "",
      suppressed: "",
      source_ip: "",
    });
  const [focus, setFocus] = useState<Alert | null>(null),
    [evidence, setEvidence] = useState<Evidence | null>(null),
    [reason, setReason] = useState("");
  const [error, setError] = useState(""),
    [pollError, setPollError] = useState(""),
    [notice, setNotice] = useState(""),
    [busy, setBusy] = useState(false);
  const [scenario, setScenario] = useState("phase0-controlled-network-v1"),
    [speed, setSpeed] = useState(10),
    [replayRule, setReplayRule] = useState("phase2-rules-v1"),
    [allowScanner, setAllowScanner] = useState(false);
  const [ruleVersions, setRuleVersions] = useState<Rule[]>([]),
    [indicatorVersions, setIndicatorVersions] = useState<Indicator[]>([]),
    [ruleText, setRuleText] = useState(""),
    [indicatorText, setIndicatorText] = useState("");
  const [hosts, setHosts] = useState<Host[]>([]),
    [host, setHost] = useState<HostDetail | null>(null),
    [hostEvents, setHostEvents] = useState<EventItem[]>([]),
    [eventCursor, setEventCursor] = useState<string | null>(null);
  const [suppressions, setSuppressions] = useState<
      { suppression: Suppression; validity_mode: string; audited_at: string }[]
    >([]),
    [supDetector, setSupDetector] = useState("vertical_tcp_scan"),
    [supSource, setSupSource] = useState("192.0.2.10"),
    [supDestination, setSupDestination] = useState("192.0.2.20"),
    [supReason, setSupReason] = useState(""),
    [supMode, setSupMode] = useState("scenario_interval");
  const run = runs.find((r) => r.run_id === selected);
  const isOperator = session?.role === "operator";
  async function api(path: string, method = "GET", body?: unknown) {
    const response = await fetch("/api/v1" + path, {
      method,
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        ...(session ? { "X-CSRF-Token": session.csrf_token } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const data = await response.json();
    if (!response.ok) {
      if (response.status === 401) setSession(null);
      throw Error(data.message || "Request failed");
    }
    return data;
  }
  async function action(fn: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await fn();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function configs() {
    const [r, i] = await Promise.all([api("/rules"), api("/indicators")]);
    setRuleVersions(r.items);
    setIndicatorVersions(i.items);
  }
  useEffect(() => {
    fetch("/runtime-config.json")
      .then((r) => {
        if (!r.ok) throw Error("Runtime config unavailable");
        return r.json();
      })
      .then((config) => {
        const url = new URL(config.grafana_url);
        if (["http:", "https:"].includes(url.protocol)) setGrafanaUrl(url.href);
      })
      .catch(() => setGrafanaUrl(null));
  }, []);
  useEffect(() => {
    api("/session")
      .then(setSession)
      .catch(() => {})
      .finally(() => setReady(true));
  }, []);
  useEffect(() => {
    if (session) configs().catch((e) => setError(e.message));
  }, [session]);
  useEffect(() => {
    if (!session) return;
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      try {
        if (page === "Operations" && session?.role === "operator") {
          const [state, dlq] = await Promise.all([
            api("/operations"),
            api("/deadletters"),
          ]);
          if (!alive) return;
          setOps(state);
          setQuarantine(dlq.items);
        }
        if (page === "Evaluation") {
          const result = await api("/evaluation");
          if (!alive) return;
          setEvaluation(result);
        }
        const all = await api("/runs");
        if (!alive) return;
        setRuns(all.items);
        const id = selected || all.items[0]?.run_id;
        if (id) {
          if (!selected) setSelected(id);
          const current = all.items.find((r: Run) => r.run_id === id);
          if (current) {
            const query = new URLSearchParams({
              scope_id: current.scope_id,
              ...Object.fromEntries(
                Object.entries(filters).filter(([, v]) => v),
              ),
              ...(cursor ? { cursor } : {}),
            });
            const [o, a] = await Promise.all([
              api("/overview?scope_id=" + current.scope_id),
              api("/alerts?" + query),
            ]);
            if (!alive) return;
            setOverview(o);
            setAlerts(a.items);
            setNextCursor(a.next_cursor);
            if (page === "Investigation" && focus) {
              const [f, e] = await Promise.all([
                api("/alerts/" + focus.alert_id),
                api("/alerts/" + focus.alert_id + "/evidence"),
              ]);
              if (!alive) return;
              setFocus(f);
              setEvidence(e);
            }
          }
        }
        if (alive) setPollError("");
      } catch (e) {
        if (alive) setPollError("Updates paused: " + (e as Error).message);
      } finally {
        if (alive) timer = setTimeout(poll, 2000);
      }
    }
    poll();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [session, selected, filters, cursor, page, focus?.alert_id]);
  useEffect(() => {
    if (!session || !run) return;
    let alive = true;
    const path =
      page === "Hosts"
        ? "/hosts"
        : page === "Suppressions"
          ? "/suppressions"
          : null;
    if (path)
      api(path + "?scope_id=" + run.scope_id)
        .then((data) => {
          if (alive) {
            if (page === "Hosts") setHosts(data.items);
            else setSuppressions(data.items);
          }
        })
        .catch((e) => {
          if (alive) setError(e.message);
        });
    return () => {
      alive = false;
    };
  }, [session, selected, page, run?.status]);
  async function inspect(a: Alert) {
    await action(async () => {
      const detail = await api("/alerts/" + a.alert_id + "/evidence");
      setFocus(a);
      setEvidence(detail);
      setReason("");
      setPage("Investigation");
    });
  }
  async function inspectHost(ip: string) {
    if (!run) return;
    await action(async () => {
      const [h, e] = await Promise.all([
        api("/hosts/" + encodeURIComponent(ip) + "?scope_id=" + run.scope_id),
        api(
          "/events?" +
            new URLSearchParams({ scope_id: run.scope_id, host_ip: ip }),
        ),
      ]);
      setHost(h);
      setHostEvents(e.items);
      setEventCursor(e.next_cursor);
      setPage("Hosts");
    });
  }
  function selectRun(id: string) {
    setSelected(id);
    setFocus(null);
    setEvidence(null);
    setHost(null);
    setHosts([]);
    setHostEvents([]);
    setCursor("");
    setFilters({
      detector_id: "",
      severity: "",
      status: "",
      suppressed: "",
      source_ip: "",
    });
    setSourceDraft("");
    setOverview(null);
    setAlerts([]);
    setNotice("");
    if (page === "Investigation") setPage("Overview");
  }
  if (!ready)
    return (
      <div className="login">
        <h1>TraceHawk</h1>
        <p>Checking your session…</p>
      </div>
    );
  if (!session)
    return (
      <div className="login">
        <div className="logo">
          TraceHawk<span>NETWORK INVESTIGATIONS</span>
        </div>
        <h1>Sign in to your local workspace</h1>
        <p>Replay network traffic and investigate explainable detections.</p>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            action(async () => {
              setSession(
                await api("/session/login", "POST", { username, password }),
              );
              setPassword("");
            });
          }}
        >
          <label>
            Username
            <input
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </label>
          <label>
            Password
            <input
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </label>
          {error && (
            <p role="alert" className="error">
              {error}
            </p>
          )}
          <button disabled={busy}>Sign in</button>
        </form>
        <p className="note">
          Local credentials are generated by setup. See tmp/credentials.json.
        </p>
      </div>
    );
  return (
    <>
      <aside>
        <div className="logo">
          TraceHawk<span>NETWORK INVESTIGATIONS</span>
        </div>
        <nav>
          {[
            "Overview",
            "Alerts",
            "Investigation",
            "Hosts",
            "Replay",
            "Rules",
            "Suppressions",
            "Evaluation",
            ...(isOperator ? ["Operations"] : []),
          ].map((p) => (
            <button
              key={p}
              aria-current={page === p ? "page" : undefined}
              disabled={p === "Investigation" && !focus}
              onClick={() => setPage(p)}
            >
              {p}
            </button>
          ))}
        </nav>
        <footer>
          <span>
            {session.username} · {session.role}
          </span>
          <button
            onClick={() =>
              action(async () => {
                await api("/session/logout", "POST", {});
                setSession(null);
                setPage("Overview");
                setOps(null);
                setQuarantine([]);
                setReviewReason("");
                selectRun("");
              })
            }
          >
            Sign out
          </button>
          <small>Replay laboratory · v1.0</small>
        </footer>
      </aside>
      <main>
        <header>
          <span>Workspace / Network monitoring</span>
          <label>
            Selected run
            <select
              aria-label="Selected run"
              value={selected}
              onChange={(e) => selectRun(e.target.value)}
            >
              <option value="">No run selected</option>
              {runs.map((r) => (
                <option key={r.run_id} value={r.run_id}>
                  {r.scenario_id} · {r.run_id.slice(0, 6)} · {r.status}
                </option>
              ))}
            </select>
          </label>
        </header>
        <div className="banner">
          CONTROLLED REPLAY · Offline constructed traffic processed by Zeek.
          Default indicators are fictional development data.
        </div>
        {(error || pollError) && (
          <div role="alert" className="error">
            {error || pollError}
          </div>
        )}
        {notice && (
          <div role="status" className="notice">
            {notice === "Replay queued" && run?.status === "completed"
              ? "Replay completed"
              : notice}
          </div>
        )}
        {page === "Evaluation" && (
          <section className="panel">
            <h2>Measured evaluation</h2>
            <p>{evaluation?.scope || "Loading versioned results…"}</p>
            {evaluation && (
              <>
                <p>
                  {evaluation.captures} frozen captures ·{" "}
                  {evaluation.held_out_captures} held out ·{" "}
                  {evaluation.benign_alerts} benign actionable alerts ·{" "}
                  {evaluation.suppressed_alerts} authorized finding suppressed.
                </p>
                <h3>Held-out rule episodes</h3>
                <table>
                  <thead>
                    <tr>
                      <th>Family</th>
                      <th>TP / FP / FN</th>
                      <th>Precision</th>
                      <th>Recall</th>
                    </tr>
                  </thead>
                  <tbody>
                    {evaluation.rules.map((r) => (
                      <tr key={r.family}>
                        <td>
                          {r.family}
                          {!r.implemented && " (unsupported)"}
                        </td>
                        <td>
                          {r.tp} / {r.fp} / {r.fn}
                        </td>
                        <td>
                          {r.precision === null
                            ? "—"
                            : `${(r.precision * 100).toFixed(1)}%`}
                        </td>
                        <td>
                          {r.recall === null
                            ? "—"
                            : `${(r.recall * 100).toFixed(1)}%`}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <p>
                  Slow scans were missed. Legitimate service retries and DNS
                  errors caused false positives. These small synthetic fractions
                  do not establish real-world detection accuracy.
                </p>
                <h3>Offline anomaly experiment</h3>
                <p>
                  Isolation Forest added{" "}
                  {evaluation.model.new_true_positive_captures.length} new
                  true-positive captures. Default enabled:{" "}
                  {evaluation.model.default_enabled ? "yes" : "no"}.
                </p>
                <p>{evaluation.model.recommendation}</p>
                <h3>Short pipeline load trials</h3>
                <p>
                  40 events/s offered for 12 seconds, two repeats. Real
                  Kafka/PostgreSQL; separate synthetic generator; monitoring on.
                  Two-second latency warm-up. Rates below include drain time.
                </p>
                <table>
                  <thead>
                    <tr>
                      <th>Workers</th>
                      <th>Sources</th>
                      <th>Durable events/s</th>
                      <th>Max observed p95</th>
                    </tr>
                  </thead>
                  <tbody>
                    {evaluation.short_trials.map((r) => (
                      <tr key={`${r.workers}:${r.sources}`}>
                        <td>{r.workers}</td>
                        <td>{r.sources}</td>
                        <td>{r.mean_durable_events_per_s.toFixed(2)}</td>
                        <td>{r.max_p95_durable_observation_s.toFixed(3)} s</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <p>
                  500 events/s × 600-second target:{" "}
                  {evaluation.engineering_target.completed
                    ? "completed"
                    : "failed early"}
                  , after{" "}
                  {evaluation.engineering_target.actually_published_s.toFixed(
                    2,
                  )}{" "}
                  s of publication.{" "}
                  {evaluation.engineering_target.early_stop_reason}
                </p>
                <p>
                  Durable latency includes observer polling. The ten-minute
                  capacity target remains unestablished. Loaded scan recovery
                  parity:{" "}
                  {evaluation.recovery_final_effect_parity
                    ? "passed"
                    : "failed"}
                  .
                </p>
              </>
            )}
          </section>
        )}
        {page === "Operations" && isOperator && (
          <section className="panel">
            <h2>Pipeline operations</h2>
            <p>
              Controlled offline replay · durable database checkpoints ·
              at-least-once Kafka alert delivery.
            </p>
            <p>
              Pipeline:{" "}
              <strong>
                {pollError ? "unavailable" : ops?.status || "loading"}
              </strong>
            </p>
            {grafanaUrl && (
              <a href={grafanaUrl} target="_blank" rel="noreferrer">
                Open Grafana operations dashboard
              </a>
            )}
            {ops && (
              <>
                <h3>Workers</h3>
                <table>
                  <thead>
                    <tr>
                      <th>Worker</th>
                      <th>Status</th>
                      <th>Heartbeat</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ops.workers.map((w) => (
                      <tr key={w.component}>
                        <td>{w.component}</td>
                        <td>{w.status}</td>
                        <td>{w.fresh ? "current" : "stale"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <h3>Partition ownership</h3>
                <table>
                  <thead>
                    <tr>
                      <th>Partition</th>
                      <th>Owner</th>
                      <th>Epoch</th>
                      <th>Next offset</th>
                      <th>Lag</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ops.partitions.map((p) => (
                      <tr key={p.partition}>
                        <td>{p.partition}</td>
                        <td>
                          {p.owner_id?.split(":")[0] || "unassigned"}
                          {!p.fresh && " (stale)"}
                        </td>
                        <td>{p.ownership_epoch}</td>
                        <td>{p.next_offset}</td>
                        <td>{p.lag}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <p>
                  Pending alert updates: {ops.queues.pending_alert_updates} ·
                  Pending quarantine delivery: {ops.queues.pending_deadletters}{" "}
                  · Unreviewed records: {ops.queues.unreviewed_deadletters}
                </p>
              </>
            )}
            <h3>Quarantined records</h3>
            <p>
              Malformed input is retained as metadata and a SHA-256 fingerprint.
              Raw payloads are excluded. Reviewing acknowledges investigation;
              it does not replay the rejected record.
            </p>
            <label>
              Review reason
              <input
                value={reviewReason}
                onChange={(e) => setReviewReason(e.target.value)}
                maxLength={500}
              />
            </label>
            <table>
              <thead>
                <tr>
                  <th>Partition / offset</th>
                  <th>Reason</th>
                  <th>Delivery</th>
                  <th>Review</th>
                </tr>
              </thead>
              <tbody>
                {quarantine.map((q) => (
                  <tr key={`${q.partition}:${q.broker_offset}`}>
                    <td>
                      {q.partition} / {q.broker_offset}
                    </td>
                    <td>{q.reason}</td>
                    <td>{q.delivered_at ? "acknowledged" : "pending"}</td>
                    <td>
                      {q.reviewed_at ? (
                        "reviewed"
                      ) : (
                        <button
                          disabled={busy || !reviewReason.trim()}
                          onClick={() =>
                            action(async () => {
                              await api(
                                `/deadletters/${q.partition}/${q.broker_offset}/review`,
                                "POST",
                                { reason: reviewReason },
                              );
                              setReviewReason("");
                              setNotice("Quarantine review recorded");
                            })
                          }
                        >
                          Record review
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!quarantine.length && <p>No quarantined records.</p>}
          </section>
        )}
        {page === "Overview" && (
          <>
            <h1>Network overview</h1>
            <p>Understand activity, then follow the evidence.</p>
            <div className="stats">
              <Card
                label="Events inspected"
                value={overview?.event_count ?? "—"}
              />
              <Card
                label="Open unsuppressed alerts"
                value={overview?.open_alert_count ?? "—"}
              />
              <Card
                label="Suppressed alerts"
                value={overview?.suppressed_alert_count ?? "—"}
              />
              <Card
                label="Pipeline"
                value={overview?.pipeline_status ?? "No run"}
              />
            </div>
            {run ? (
              <section className="card">
                <h2>Current run · {run.status}</h2>
                <p>
                  {run.scenario_id} · {run.processed_records}/
                  {run.total_records} source records published ·{" "}
                  {run.rule_version}
                </p>
                <progress
                  max={run.total_records || 1}
                  value={run.processed_records}
                />
                <p className="note">
                  Completion waits for durable processing of all three partition
                  barriers. Indicator snapshot:{" "}
                  {run.indicator_version ?? "Disabled"}.
                </p>
              </section>
            ) : (
              <section className="card">
                <h2>Start your first investigation</h2>
                <p>
                  Choose an offline scenario and an immutable rule snapshot.
                </p>
                <button onClick={() => setPage("Replay")}>
                  Choose a scenario
                </button>
              </section>
            )}
            <AlertTable alerts={alerts} inspect={inspect} />
          </>
        )}
        {page === "Alerts" && (
          <>
            <h1>Alert inbox</h1>
            <p>
              Filters query persisted findings for the selected run. Suppressed
              results retain evidence.
            </p>
            <section className="card filters">
              {(
                ["detector_id", "severity", "status", "suppressed"] as const
              ).map((key) => (
                <label key={key}>
                  {key === "detector_id"
                    ? "Detector"
                    : key === "suppressed"
                      ? "Suppression"
                      : key === "severity"
                        ? "Severity"
                        : "Status"}
                  <select
                    aria-label={"Filter " + key}
                    value={filters[key]}
                    onChange={(e) => {
                      setFilters({ ...filters, [key]: e.target.value });
                      setCursor("");
                    }}
                  >
                    <option value="">All</option>
                    {(key === "detector_id"
                      ? Object.keys(detectors)
                      : key === "severity"
                        ? ["low", "medium", "high", "critical"]
                        : key === "status"
                          ? ["open", "acknowledged", "resolved"]
                          : ["false", "true"]
                    ).map((v) => (
                      <option key={v} value={v}>
                        {key === "detector_id"
                          ? detectors[v]
                          : key === "suppressed"
                            ? v === "true"
                              ? "Suppressed"
                              : "Unsuppressed"
                            : v}
                      </option>
                    ))}
                  </select>
                </label>
              ))}
              <label>
                Source IP
                <input
                  aria-label="Filter source IP"
                  value={sourceDraft}
                  onChange={(e) => setSourceDraft(e.target.value)}
                  placeholder="Exact address"
                />
                <button
                  onClick={() => {
                    setFilters({ ...filters, source_ip: sourceDraft.trim() });
                    setCursor("");
                  }}
                >
                  Apply source filter
                </button>
              </label>
            </section>
            <AlertTable alerts={alerts} inspect={inspect} />
            <div className="actions">
              <button disabled={!cursor} onClick={() => setCursor("")}>
                First page
              </button>
              <button
                disabled={!nextCursor}
                onClick={() => setCursor(nextCursor!)}
              >
                Next page
              </button>
            </div>
          </>
        )}
        {page === "Investigation" && focus && (
          <>
            <div className="heading">
              <div>
                <h1>{detectors[focus.detector_id]}</h1>
                <p>
                  <button
                    className="link"
                    onClick={() => inspectHost(focus.source_ip)}
                  >
                    {focus.source_ip}
                  </button>{" "}
                  → {focus.destination_ip ?? "DNS destinations"} ·{" "}
                  {focus.rule_version}
                </p>
              </div>
              <span className="tag">
                {focus.severity} · {focus.status}
                {focus.suppressed ? " · suppressed" : ""}
              </span>
            </div>
            <section className="card">
              <h2>Why this alert fired</h2>
              <p>{focus.explanation}</p>
              <div className="metrics">
                {Object.entries(focus.observed).map(([k, v]) => (
                  <div className="metric" key={k}>
                    <span>
                      {focus.detector_id === "known_indicator"
                        ? "Observed"
                        : "Peak"}{" "}
                      {k.replaceAll("_", " ")}
                    </span>
                    <strong>
                      {k.includes("ratio") ? (v * 100).toFixed(1) + "%" : v}
                    </strong>
                  </div>
                ))}
              </div>
              <p className="note">
                Threshold snapshot:{" "}
                {Object.entries(focus.thresholds)
                  .map(([k, v]) => k + " = " + v)
                  .join(" · ")}
              </p>
              <p className="note">
                Evidence interval: {when(focus.first_event_time_us)} —{" "}
                {when(focus.last_event_time_us)}
              </p>
              {focus.indicator_version && (
                <p>
                  Indicator version: {focus.indicator_version}. Inspect exact
                  matches below.
                </p>
              )}
              {evidence?.suppression && (
                <div className="notice">
                  <strong>Suppressed · evidence retained</strong>
                  <p>{evidence.suppression.reason}</p>
                  <small>
                    {evidence.suppression.suppression_id} · Event-time validity:{" "}
                    {when(evidence.suppression.created_at_us)} —{" "}
                    {when(evidence.suppression.expires_at_us)}
                  </small>
                </div>
              )}
            </section>
            <section className="card">
              <h2>Evidence timeline</h2>
              <Timeline bins={evidence?.timeline ?? []} />
            </section>
            {Boolean(evidence?.matched_windows.length) && (
              <section className="card">
                <h2>Measured matching windows</h2>
                <p className="note">
                  Each row preserves its own counts and ratios. Peak summary
                  values can come from different windows.
                </p>
                <div className="tablewrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Window end (UTC)</th>
                        <th>Measured features</th>
                      </tr>
                    </thead>
                    <tbody>
                      {evidence?.matched_windows.map((w) => (
                        <tr key={w.window_end_us}>
                          <td>{when(w.window_end_us)}</td>
                          <td>
                            {Object.entries(w.observed)
                              .map(
                                ([k, v]) =>
                                  k +
                                  ": " +
                                  (k.includes("ratio")
                                    ? (v * 100).toFixed(1) + "%"
                                    : v),
                              )
                              .join(" · ")}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            )}
            {Boolean(evidence?.indicator_matches.length) && (
              <section className="card">
                <h2>Exact indicator matches</h2>
                <p className="note">
                  The default list is fictional. A match alone does not
                  establish compromise.
                </p>
                {evidence?.indicator_matches.map((m, i) => (
                  <p key={i}>
                    <strong>
                      {m.kind}: {m.value}
                    </strong>{" "}
                    · {m.description}
                  </p>
                ))}
              </section>
            )}
            <section className="card">
              <h2>
                {focus.detector_id === "vertical_tcp_scan" ||
                focus.detector_id === "failed_tcp_connections"
                  ? "Supporting connections"
                  : "Supporting events"}{" "}
                ({focus.evidence_total_count})
              </h2>
              <EventTable
                items={(evidence?.items ?? []).map((event) => ({
                  event,
                  eligible_for_temporal_rules:
                    evidence?.event_eligibility.find(
                      (e) => e.event_id === event.event_id,
                    )?.eligible_for_temporal_rules ?? true,
                  exclusion_reason:
                    evidence?.event_eligibility.find(
                      (e) => e.event_id === event.event_id,
                    )?.exclusion_reason ?? null,
                }))}
              />
              <p className="note">
                Zeek {evidence?.items[0]?.provenance.zeek_version} ·{" "}
                {evidence?.items[0]?.provenance.capture_id}.{" "}
                {focus.evidence_truncated
                  ? "Evidence is capped at 200 rows; total and timeline counts remain exact."
                  : "All supporting events shown."}
              </p>
            </section>
            <section className="card">
              <h2>Record a disposition</h2>
              <label>
                Investigation reason
                <input
                  value={reason}
                  maxLength={512}
                  onChange={(e) => setReason(e.target.value)}
                />
              </label>
              <div className="actions">
                {["acknowledged", "resolved", "open"].map((status) => (
                  <button
                    key={status}
                    disabled={busy || !reason.trim()}
                    onClick={() =>
                      action(async () => {
                        setFocus(
                          await api(
                            "/alerts/" + focus.alert_id + "/status",
                            "PATCH",
                            { status, reason },
                          ),
                        );
                        setEvidence(
                          await api("/alerts/" + focus.alert_id + "/evidence"),
                        );
                        setNotice("Disposition saved: " + status);
                      })
                    }
                  >
                    {status === "open"
                      ? "Reopen"
                      : status === "resolved"
                        ? "Resolve"
                        : "Acknowledge"}
                  </button>
                ))}
                {isOperator && (
                  <button
                    className="secondary"
                    onClick={() => {
                      setSupDetector(focus.detector_id);
                      setSupSource(focus.source_ip);
                      setSupDestination(focus.destination_ip ?? "");
                      setPage("Suppressions");
                    }}
                  >
                    Configure future suppression
                  </button>
                )}
              </div>
              <h2>Recorded activity</h2>
              {evidence?.history.map((h, i) => (
                <p className="note" key={i}>
                  {h.created_at} · {h.actor} · {h.action}
                  {typeof h.details.reason === "string"
                    ? " · " + h.details.reason
                    : ""}
                </p>
              ))}
            </section>
          </>
        )}
        {page === "Hosts" && (
          <>
            <h1>Host investigation</h1>
            <p>Activity and coverage for hosts in the selected replay.</p>
            <section className="card">
              <h2>Observed hosts</h2>
              <div className="tablewrap">
                <table>
                  <thead>
                    <tr>
                      <th>Address</th>
                      <th>Events</th>
                      <th>Outbound / inbound</th>
                      <th>Alerts</th>
                    </tr>
                  </thead>
                  <tbody>
                    {hosts.map((h) => (
                      <tr key={h.address}>
                        <td>
                          <button
                            className="link"
                            onClick={() => inspectHost(h.address)}
                          >
                            {h.address}
                          </button>
                        </td>
                        <td>{h.event_count}</td>
                        <td>
                          {h.outbound} / {h.inbound}
                        </td>
                        <td>{h.alert_count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {!hosts.length && (
                <p>
                  No hosts available. Select a replay with inspected events.
                </p>
              )}
            </section>
            {host && (
              <>
                <section className="card">
                  <h2>Host {host.address}</h2>
                  <p>{host.event_count} observed events</p>
                  <div className="metrics">
                    {Object.entries(host.coverage).map(([k, v]) => (
                      <div className="metric" key={k}>
                        <span>{k.replaceAll("_", " ")}</span>
                        <strong>{v}</strong>
                      </div>
                    ))}
                  </div>
                  <p className="note">
                    Missing TCP state or OTH remains unknown. Missing DNS
                    response code is excluded from failure ratios. Absent
                    duration retains its labeled original-start time fallback.
                  </p>
                  <Timeline bins={host.timeline} />
                </section>
                <AlertTable alerts={host.alerts} inspect={inspect} />
                <section className="card">
                  <h2>Host event timeline</h2>
                  <EventTable items={hostEvents} />
                  <button
                    disabled={!eventCursor || busy}
                    onClick={() =>
                      action(async () => {
                        const result = await api(
                          "/events?" +
                            new URLSearchParams({
                              scope_id: run!.scope_id,
                              host_ip: host.address,
                              cursor: eventCursor!,
                            }),
                        );
                        setHostEvents([...hostEvents, ...result.items]);
                        setEventCursor(result.next_cursor);
                      })
                    }
                  >
                    Load more events
                  </button>
                </section>
              </>
            )}
          </>
        )}
        {page === "Replay" && (
          <>
            <h1>Scenario replay</h1>
            <p>A reproducible path from network telemetry to investigation.</p>
            <section className="card">
              <label>
                Scenario
                <select
                  aria-label="Scenario"
                  value={scenario}
                  onChange={(e) => {
                    setScenario(e.target.value);
                    setAllowScanner(false);
                  }}
                >
                  <option value="phase0-controlled-network-v1">
                    Controlled scan + DNS traffic
                  </option>
                  <option value="benign-network-v1">
                    Benign network baseline
                  </option>
                </select>
              </label>
              <p>
                {scenario === "benign-network-v1"
                  ? "Successful DNS and one normal TCP connection. Expected no alerts under the default snapshot."
                  : "24 scan connections, three absent responses and 40 DNS responses. Four detector types are enabled in the Phase 2 snapshot."}
              </p>
              <label>
                Playback speed
                <select
                  aria-label="Playback speed"
                  value={speed}
                  onChange={(e) => setSpeed(Number(e.target.value))}
                >
                  {[1, 5, 10].map((s) => (
                    <option key={s} value={s}>
                      {s}×
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Rule snapshot
                <select
                  aria-label="Rule snapshot"
                  value={replayRule}
                  onChange={(e) => setReplayRule(e.target.value)}
                >
                  {ruleVersions.map((r) => (
                    <option key={r.version} value={r.version}>
                      {r.version}
                    </option>
                  ))}
                </select>
              </label>
              <p className="note">
                Indicator snapshot:{" "}
                {ruleVersions.find((r) => r.version === replayRule)
                  ?.known_indicator.enabled
                  ? ruleVersions.find((r) => r.version === replayRule)
                      ?.known_indicator.indicator_version
                  : "Disabled"}
                . Default indicator matches use fictional data.
              </p>
              {scenario === "phase0-controlled-network-v1" && (
                <label className="check">
                  <input
                    type="checkbox"
                    checked={allowScanner}
                    onChange={(e) => setAllowScanner(e.target.checked)}
                  />
                  Authorize the lab scanner for this replay (suppress port-scan
                  alert only)
                </label>
              )}
              {allowScanner && (
                <p className="note">
                  Scoped suppression is installed before publishing. It uses the
                  capture's historical event-time interval and retains the alert
                  and evidence.
                </p>
              )}
              <button
                disabled={
                  busy ||
                  !isOperator ||
                  runs.some((r) =>
                    ["queued", "preparing", "replaying", "finalizing"].includes(
                      r.status,
                    ),
                  )
                }
                onClick={() =>
                  action(async () => {
                    const r = await api("/runs", "POST", {
                      scenario_id: scenario,
                      rule_version: replayRule,
                      playback_speed: speed,
                      ...(allowScanner
                        ? {
                            suppression_templates: [
                              {
                                detector_id: "vertical_tcp_scan",
                                source_ip: "192.0.2.10",
                                destination_ip: "192.0.2.20",
                                reason:
                                  "Authorized lab scanner for this controlled replay",
                              },
                            ],
                          }
                        : {}),
                    });
                    setRuns([r, ...runs]);
                    selectRun(r.run_id);
                    setNotice("Replay queued");
                    setPage("Overview");
                  })
                }
              >
                Start replay
              </button>
              {!isOperator && (
                <p className="note">
                  Operator permission is required to control replay.
                </p>
              )}
              {isOperator &&
                run &&
                ["queued", "preparing", "replaying", "finalizing"].includes(
                  run.status,
                ) && (
                  <button
                    className="secondary"
                    onClick={() =>
                      action(async () => {
                        await api(
                          "/runs/" + run.run_id + "/cancel",
                          "POST",
                          {},
                        );
                        setNotice(
                          "Replay cancelled; partial evidence is retained",
                        );
                      })
                    }
                  >
                    Cancel selected replay
                  </button>
                )}
            </section>
          </>
        )}
        {page === "Rules" && (
          <>
            <h1>Detection configuration</h1>
            <p>
              Publish new immutable versions. Existing runs retain their
              selected snapshots.
            </p>
            <section className="card">
              <h2>Rule versions</h2>
              <label>
                Inspect rule snapshot
                <select
                  aria-label="Inspect rule snapshot"
                  defaultValue=""
                  onChange={(e) =>
                    setRuleText(
                      JSON.stringify(
                        ruleVersions.find((r) => r.version === e.target.value),
                        null,
                        2,
                      ),
                    )
                  }
                >
                  <option value="" disabled>
                    Choose a version
                  </option>
                  {ruleVersions.map((r) => (
                    <option key={r.version}>{r.version}</option>
                  ))}
                </select>
              </label>
              <label>
                Rule JSON
                <textarea
                  aria-label="Rule JSON"
                  value={ruleText}
                  readOnly={!isOperator}
                  onChange={(e) => setRuleText(e.target.value)}
                  rows={15}
                />
              </label>
              <p className="note">
                Change the version before saving. Windows stay fixed at 60s /
                10s cadence / 30s lateness in this release.
              </p>
              <button
                disabled={!isOperator || busy || !ruleText}
                onClick={() =>
                  action(async () => {
                    const result = await api(
                      "/rules",
                      "POST",
                      JSON.parse(ruleText),
                    );
                    await configs();
                    setReplayRule(result.version);
                    setNotice("Rule snapshot created: " + result.version);
                  })
                }
              >
                Create rule version
              </button>
            </section>
            <section className="card">
              <h2>Indicator versions</h2>
              <p>
                Default entries are fictional development data. Custom lists
                must declare their provenance.
              </p>
              <label>
                Inspect indicator snapshot
                <select
                  aria-label="Inspect indicator snapshot"
                  defaultValue=""
                  onChange={(e) =>
                    setIndicatorText(
                      JSON.stringify(
                        indicatorVersions.find(
                          (i) => i.version === e.target.value,
                        ),
                        null,
                        2,
                      ),
                    )
                  }
                >
                  <option value="" disabled>
                    Choose a version
                  </option>
                  {indicatorVersions.map((i) => (
                    <option key={i.version}>{i.version}</option>
                  ))}
                </select>
              </label>
              <label>
                Indicator JSON
                <textarea
                  aria-label="Indicator JSON"
                  value={indicatorText}
                  readOnly={!isOperator}
                  onChange={(e) => setIndicatorText(e.target.value)}
                  rows={12}
                />
              </label>
              <button
                disabled={!isOperator || busy || !indicatorText}
                onClick={() =>
                  action(async () => {
                    const result = await api(
                      "/indicators",
                      "POST",
                      JSON.parse(indicatorText),
                    );
                    await configs();
                    setIndicatorText(JSON.stringify(result, null, 2));
                    setNotice("Indicator snapshot created: " + result.version);
                  })
                }
              >
                Create indicator version
              </button>
            </section>
          </>
        )}
        {page === "Suppressions" && (
          <>
            <h1>Scoped suppressions</h1>
            <p>
              Suppressions retain alerts and evidence. Existing alert episodes
              keep their original decision.
            </p>
            <section className="card">
              <h2>
                Create a suppression for{" "}
                {run?.run_id.slice(0, 6) ?? "a selected run"}
              </h2>
              <label>
                Suppression detector
                <select
                  value={supDetector}
                  onChange={(e) => setSupDetector(e.target.value)}
                >
                  {Object.entries(detectors).map(([id, label]) => (
                    <option key={id} value={id}>
                      {label}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Suppression source IP
                <input
                  value={supSource}
                  onChange={(e) => setSupSource(e.target.value)}
                />
              </label>
              <label>
                Suppression destination IP
                <input
                  value={supDestination}
                  onChange={(e) => setSupDestination(e.target.value)}
                  placeholder="Blank applies to any destination"
                />
              </label>
              <label>
                Suppression reason
                <input
                  maxLength={512}
                  value={supReason}
                  onChange={(e) => setSupReason(e.target.value)}
                />
              </label>
              <label>
                Validity time basis
                <select
                  value={supMode}
                  onChange={(e) => setSupMode(e.target.value)}
                >
                  <option value="scenario_interval">
                    Historical capture interval (controlled replay)
                  </option>
                  <option value="from_now">Wall clock: now for one hour</option>
                </select>
              </label>
              <p className="note">
                A wall-clock suppression cannot cover older replay events. Alert
                creation uses the latest contributing event time; its
                suppression decision is then frozen.
              </p>
              <button
                disabled={!isOperator || !run || busy || !supReason.trim()}
                onClick={() =>
                  action(async () => {
                    await api("/suppressions", "POST", {
                      scope_id: run!.scope_id,
                      detector_id: supDetector,
                      source_ip: supSource,
                      destination_ip: supDestination || null,
                      reason: supReason,
                      validity_mode: supMode,
                    });
                    setSuppressions(
                      (await api("/suppressions?scope_id=" + run!.scope_id))
                        .items,
                    );
                    setNotice(
                      "Suppression saved for future alert episodes. Existing alerts retain their decision.",
                    );
                  })
                }
              >
                Save suppression
              </button>
            </section>
            <section className="card">
              <h2>Recorded suppressions</h2>
              {suppressions.length ? (
                suppressions.map((s) => (
                  <article
                    className="suppression"
                    key={s.suppression.suppression_id}
                  >
                    <strong>
                      {detectors[s.suppression.detector_id]} ·{" "}
                      {s.suppression.source_ip} →{" "}
                      {s.suppression.destination_ip ?? "any destination"}
                    </strong>
                    <p>{s.suppression.reason}</p>
                    <p className="note">
                      {when(s.suppression.created_at_us)} —{" "}
                      {when(s.suppression.expires_at_us)} · {s.validity_mode}
                    </p>
                    <p className="note">
                      Recorded by {s.suppression.created_by} at {s.audited_at}.
                      ID: {s.suppression.suppression_id}
                    </p>
                  </article>
                ))
              ) : (
                <p>No suppressions in the selected run.</p>
              )}
            </section>
          </>
        )}
      </main>
    </>
  );
}
function Card({ label, value }: { label: string; value: string | number }) {
  return (
    <section className="card">
      <div className="label">{label}</div>
      <div className="value">{value}</div>
    </section>
  );
}
function AlertTable({
  alerts,
  inspect,
}: {
  alerts: Alert[];
  inspect: (a: Alert) => void;
}) {
  return (
    <section className="card">
      <h2>Security alerts</h2>
      {alerts.length ? (
        <div className="tablewrap">
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Detection</th>
                <th>Source → target</th>
                <th>Status</th>
                <th>Evidence</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((a) => (
                <tr key={a.alert_id}>
                  <td>
                    <span className="tag">{a.severity}</span>
                  </td>
                  <td>
                    <button className="link" onClick={() => inspect(a)}>
                      {detectors[a.detector_id]}
                    </button>
                  </td>
                  <td>
                    {a.source_ip} → {a.destination_ip ?? "DNS destinations"}
                  </td>
                  <td>
                    {a.status}
                    {a.suppressed ? " · suppressed" : ""}
                  </td>
                  <td>
                    {a.evidence_total_count}{" "}
                    {a.evidence_total_count === 1 ? "event" : "events"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p>
          No alerts match this view. Choose a scenario or wait for window
          finalization.
        </p>
      )}
    </section>
  );
}
function EventTable({ items }: { items: EventItem[] }) {
  return (
    <div className="tablewrap">
      <table>
        <thead>
          <tr>
            <th>Event time (UTC)</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Outcome / query</th>
            <th>Time basis</th>
          </tr>
        </thead>
        <tbody>
          {items.map(
            ({
              event: e,
              eligible_for_temporal_rules: eligible,
              exclusion_reason: reason,
            }) => (
              <tr key={e.event_id}>
                <td>{when(e.event_time_us)}</td>
                <td>
                  {e.source_ip}:{e.source_port}
                </td>
                <td>
                  {e.destination_ip}:{e.destination_port}
                </td>
                <td>
                  {e.connection
                    ? (e.connection.state ?? "Unknown TCP state")
                    : `${e.dns?.rcode === null ? "Unknown DNS outcome" : (e.dns?.rcode_name ?? e.dns?.rcode)} · ${e.dns?.query ?? "Unknown query"}`}
                  {!eligible && (
                    <small className="late">
                      Temporal features excluded:{" "}
                      {reason ?? "earlier scoped watermark"}
                    </small>
                  )}
                </td>
                <td>{e.time_basis}</td>
              </tr>
            ),
          )}
        </tbody>
      </table>
    </div>
  );
}
function Timeline({ bins }: { bins: TimelineBin[] }) {
  if (!bins.length) return <p>No timeline evidence available.</p>;
  const max = Math.max(...bins.map((b) => b.event_count)),
    width = Math.max(600, bins.length * 40),
    slot = width / bins.length;
  return (
    <figure className="timeline">
      <svg
        viewBox={`0 0 ${width} 160`}
        role="img"
        aria-label="Observed events in ten-second event-time buckets"
      >
        {bins.map((b, i) => (
          <g key={b.start_us}>
            <rect
              x={i * slot + 5}
              y={130 - (b.event_count / max) * 100}
              width={slot - 10}
              height={(b.event_count / max) * 100}
            >
              <title>
                {when(b.start_us)}: {b.event_count} events
              </title>
            </rect>
            <text
              x={i * slot + slot / 2}
              y={125 - (b.event_count / max) * 100}
              textAnchor="middle"
            >
              {b.event_count}
            </text>
            <text x={i * slot + slot / 2} y={150} textAnchor="middle">
              {new Date(b.start_us / 1000).toISOString().slice(14, 19)}
            </text>
          </g>
        ))}
      </svg>
      <figcaption>
        {bins.reduce((n, b) => n + b.event_count, 0)} observed events ·
        10-second buckets · UTC event time. {when(bins[0].start_us)} —{" "}
        {when(bins.at(-1)!.start_us + 10_000_000)}
      </figcaption>
    </figure>
  );
}
createRoot(document.getElementById("root")!).render(<App />);
