package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	schema "github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/twmb/franz-go/pkg/kgo"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

type Job struct {
	RunID      string   `json:"run_id"`
	ScopeID    string   `json:"scope_id"`
	ScenarioID string   `json:"scenario_id"`
	Generation int64    `json:"generation"`
	NextIndex  int      `json:"next_index"`
	Speed      int      `json:"speed"`
	Offsets    []*int64 `json:"source_offsets"`
	Meta       struct {
		Folder   string            `json:"folder"`
		Hashes   map[string]string `json:"log_hashes"`
		Manifest string            `json:"manifest_sha256"`
		End      int64             `json:"time_end_us"`
	} `json:"metadata"`
}

var root = env("APP_ROOT", "/app")
var client = &http.Client{Timeout: 10 * time.Second}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func identity(v any) string {
	b, e := json.Marshal(v)
	if e != nil {
		panic(e)
	}
	return sha(b)
}
func micros(n any) (int64, error) {
	value, ok := n.(json.Number)
	if !ok {
		return 0, errors.New("timestamp must be a JSON number")
	}
	r, ok := new(big.Rat).SetString(string(value))
	if !ok {
		return 0, errors.New("invalid decimal")
	}
	r.Mul(r, big.NewRat(1000000, 1))
	q, rem := new(big.Int), new(big.Int)
	q.QuoRem(r.Num(), r.Denom(), rem)
	if rem.Sign() < 0 {
		rem.Neg(rem)
	}
	cmp := new(big.Int).Lsh(rem, 1).Cmp(r.Denom())
	if cmp > 0 || (cmp == 0 && q.Bit(0) == 1) {
		if r.Sign() < 0 {
			q.Sub(q, big.NewInt(1))
		} else {
			q.Add(q, big.NewInt(1))
		}
	}
	if !q.IsInt64() {
		return 0, errors.New("time overflow")
	}
	return q.Int64(), nil
}
func murmur2(data []byte) uint32 {
	h := uint32(0x9747b28c) ^ uint32(len(data))
	m := uint32(0x5bd1e995)
	for len(data) >= 4 {
		k := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
		k *= m
		k ^= k >> 24
		k *= m
		h *= m
		h ^= k
		data = data[4:]
	}
	switch len(data) {
	case 3:
		h ^= uint32(data[2]) << 16
		fallthrough
	case 2:
		h ^= uint32(data[1]) << 8
		fallthrough
	case 1:
		h ^= uint32(data[0])
		h *= m
	}
	h ^= h >> 13
	h *= m
	h ^= h >> 15
	return h
}
func partition(scope, ip string) int32 {
	b, _ := json.Marshal([]string{scope, ip})
	return int32((murmur2(b) & 0x7fffffff) % 3)
}
func normalize(r map[string]any, job Job, kind, generation string, offset int64) (map[string]any, error) {
	original, e := micros(r["ts"])
	if e != nil {
		return nil, e
	}
	var duration any
	eventTime := original
	basis := "dns_transaction_start"
	if kind == "conn" {
		basis = "original_start_fallback"
		if r["duration"] != nil {
			d, e := micros(r["duration"])
			if e != nil {
				return nil, e
			}
			duration = d
			eventTime += d
			basis = "connection_activity_end"
		}
	}
	src := net.ParseIP(fmt.Sprint(r["id.orig_h"]))
	dst := net.ParseIP(fmt.Sprint(r["id.resp_h"]))
	if src == nil || dst == nil {
		return nil, errors.New("invalid address")
	}
	eventKind := "dns"
	var connection, dns any
	if kind == "conn" {
		eventKind = "connection"
		connection = map[string]any{"state": r["conn_state"], "duration_us": duration, "orig_bytes": r["orig_bytes"], "resp_bytes": r["resp_bytes"], "missed_bytes": r["missed_bytes"]}
	} else {
		query := r["query"]
		if q, ok := query.(string); ok {
			query = strings.TrimSuffix(strings.ToLower(q), ".")
		}
		answers := r["answers"]
		if answers == nil {
			answers = []any{}
		}
		dns = map[string]any{"query": query, "rcode": r["rcode"], "rcode_name": r["rcode_name"], "qtype": r["qtype"], "trans_id": r["trans_id"], "answers": answers}
	}
	now := time.Now().UnixMicro()
	return map[string]any{"schema_version": "1.0", "event_id": identity([]any{job.ScopeID, "zeek-offline", generation, kind, offset}), "scope_id": job.ScopeID, "sensor_id": "zeek-offline", "run_id": job.RunID, "event_kind": eventKind, "event_time_us": eventTime, "original_timestamp_us": original, "ingested_at_us": now, "published_at_us": now, "time_basis": basis, "source_ip": src.String(), "destination_ip": dst.String(), "source_port": r["id.orig_p"], "destination_port": r["id.resp_p"], "protocol": r["proto"], "zeek_uid": r["uid"], "provenance": map[string]any{"log_kind": kind, "source_generation_id": generation, "record_offset": offset, "zeek_version": "8.0.10", "capture_id": job.ScenarioID, "input_mode": "controlled_pcap"}, "connection": connection, "dns": dns}, nil
}
func records(job Job, validator *schema.Schema) ([]map[string]any, error) {
	return recordsWithEvaluation(job, validator, false)
}
func recordsWithEvaluation(job Job, validator *schema.Schema, evaluation bool) ([]map[string]any, error) {
	if job.Meta.Folder != "scenarios/phase0" && job.Meta.Folder != "scenarios/phase1-benign" && !evaluation {
		return nil, errors.New("unregistered source")
	}
	result := []map[string]any{}
	for _, kind := range []string{"conn", "dns"} {
		path := filepath.Join(root, job.Meta.Folder, "zeek", kind+".log")
		info, e := os.Stat(path)
		if e != nil {
			return nil, e
		}
		if info.Size() > 10*1024*1024 {
			return nil, errors.New("source too large")
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return nil, e
		}
		generation := sha(b)
		if generation != job.Meta.Hashes[kind] {
			return nil, errors.New("source changed")
		}
		scanner := bufio.NewScanner(bytes.NewReader(b))
		scanner.Buffer(make([]byte, 65536), 1024*1024)
		scanner.Split(func(b []byte, eof bool) (int, []byte, error) {
			if i := bytes.IndexByte(b, '\n'); i >= 0 {
				return i + 1, b[:i+1], nil
			}
			if eof && len(b) > 0 {
				return 0, nil, errors.New("partial JSON line")
			}
			return 0, nil, nil
		})
		var offset int64
		for scanner.Scan() {
			line := scanner.Bytes()
			var r map[string]any
			dec := json.NewDecoder(bytes.NewReader(line))
			dec.UseNumber()
			if e := dec.Decode(&r); e != nil {
				return nil, e
			}
			var extra any
			if e := dec.Decode(&extra); e != io.EOF {
				return nil, errors.New("multiple JSON values on one line")
			}
			v, e := normalize(r, job, kind, generation, offset)
			if e != nil {
				return nil, e
			}
			offset += int64(len(line))
			raw, _ := json.Marshal(v)
			if len(raw) > 65536 {
				return nil, errors.New("event too large")
			}
			dec = json.NewDecoder(bytes.NewReader(raw))
			dec.UseNumber()
			var check any
			_ = dec.Decode(&check)
			if e = validator.Validate(check); e != nil {
				return nil, errors.New("event contract rejected")
			}
			result = append(result, v)
		}
		if e = scanner.Err(); e != nil {
			return nil, e
		}
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i]["event_time_us"].(int64), result[j]["event_time_us"].(int64)
		if a == b {
			return result[i]["event_id"].(string) < result[j]["event_id"].(string)
		}
		return a < b
	})
	return result, nil
}
func request(ctx context.Context, path string, body any, out any) error {
	b, _ := json.Marshal(body)
	req, e := http.NewRequestWithContext(ctx, "POST", env("API_URL", "http://api:8100")+path, bytes.NewReader(b))
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+os.Getenv("INTERNAL_TOKEN"))
	req.Header.Set("Content-Type", "application/json")
	r, e := client.Do(req)
	if e != nil {
		workerState("paused")
		return e
	}
	defer r.Body.Close()
	if r.StatusCode == 204 {
		if r.Header.Get("X-TraceHawk-State") == "paused" {
			workerState("paused")
		} else {
			workerState("ready")
		}
		return io.EOF
	}
	if r.StatusCode/100 != 2 {
		workerState("paused")
		return fmt.Errorf("coordinator status %d", r.StatusCode)
	}
	workerState("ready")
	if out != nil {
		return json.NewDecoder(io.LimitReader(r.Body, 65536)).Decode(out)
	}
	return nil
}
func checkpoint(ctx context.Context, j Job, finish bool, problem bool) error {
	return request(ctx, "/internal/jobs/"+j.RunID+"/checkpoint", map[string]any{"generation": j.Generation, "next_index": j.NextIndex, "source_offsets": j.Offsets, "finish": finish, "error": problem}, nil)
}

type sourceError struct{ error }

func replay(ctx context.Context, j Job, k *kgo.Client, v *schema.Schema) error {
	rows, e := records(j, v)
	if e != nil {
		return sourceError{e}
	}
	if j.NextIndex > len(rows) {
		return errors.New("checkpoint outside source")
	}
	if len(j.Offsets) != 3 {
		return errors.New("invalid offsets")
	}
	start := j.NextIndex
	for i := j.NextIndex; i < len(rows); i++ {
		if i > start {
			delay := time.Duration(rows[i]["event_time_us"].(int64)-rows[i-1]["event_time_us"].(int64)) * time.Microsecond / time.Duration(j.Speed)
			if delay > 0 {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(delay):
				}
			}
		}
		rows[i]["published_at_us"] = time.Now().UnixMicro()
		p := partition(j.ScopeID, rows[i]["source_ip"].(string))
		b, _ := json.Marshal(rows[i])
		key, _ := json.Marshal([]string{j.ScopeID, rows[i]["source_ip"].(string)})
		rec := &kgo.Record{Topic: "tracehawk.events.v1", Partition: p, Key: key, Value: b}
		if e = k.ProduceSync(ctx, rec).FirstErr(); e != nil {
			workerState("paused")
			return e
		}
		publishedRecords.Add(1)
		workerState("ready")
		// Test-only crash point is one-shot on a persistent private fault marker.
		if env("FAULT_AFTER_ACK", "0") == "1" {
			f, e := os.OpenFile("/state/fault-used", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e == nil {
				f.Close()
				os.Exit(17)
			}
		}
		off := rec.Offset
		j.Offsets[p] = &off
		j.NextIndex = i + 1
		if e = checkpoint(ctx, j, false, false); e != nil {
			return e
		}
	}
	final := (j.Meta.End+9999999)/10000000*10000000 + 60000000
	for p := int32(0); p < 3; p++ {
		control := map[string]any{"schema_version": "1.0", "control_kind": "replay_partition_complete", "scope_id": j.ScopeID, "run_id": j.RunID, "producer_generation": j.Generation, "partition": p, "last_data_offset": j.Offsets[p], "final_watermark_us": final, "manifest_sha256": j.Meta.Manifest}
		b, _ := json.Marshal(control)
		if e = k.ProduceSync(ctx, &kgo.Record{Topic: "tracehawk.events.v1", Partition: p, Value: b}).FirstErr(); e != nil {
			return e
		}
	}
	return checkpoint(ctx, j, true, false)
}
func main() {
	if len(os.Args) == 4 && os.Args[1] == "--normalize-evaluation" {
		if err := normalizeEvaluation(os.Args[2], os.Args[3]); err != nil {
			fmt.Println("Evaluation normalization failed:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--healthcheck" {
		probeCheck()
		return
	}
	startProbes()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	compiler := schema.NewCompiler()
	compiler.AssertFormat()
	v, e := compiler.Compile(filepath.Join(root, "contracts/schemas/event.json"))
	if e != nil {
		panic(e)
	}
	k, e := kgo.NewClient(kgo.SeedBrokers(env("KAFKA_BROKERS", "kafka:9092")), kgo.RecordPartitioner(kgo.ManualPartitioner()), kgo.MaxBufferedRecords(100), kgo.MaxBufferedBytes(1024*1024), kgo.RecordDeliveryTimeout(5*time.Second), kgo.ProduceRequestTimeout(3*time.Second))
	if e != nil {
		panic(e)
	}
	defer k.Close()
	if len(os.Getenv("INTERNAL_TOKEN")) < 32 {
		panic("Internal credential missing")
	}
	for ctx.Err() == nil {
		var j Job
		e = request(ctx, "/internal/jobs/claim", map[string]any{}, &j)
		if e == nil {
			if e = replay(ctx, j, k, v); e != nil {
				fmt.Printf("{\"component\":\"collector\",\"event\":\"replay_interrupted\",\"error_type\":\"%T\"}\n", e)
				var permanent sourceError
				if ctx.Err() == nil && errors.As(e, &permanent) {
					_ = checkpoint(ctx, j, false, true)
				}
			}
		} else if !errors.Is(e, io.EOF) {
			fmt.Println(`{"component":"collector","event":"coordinator_unavailable"}`)
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
}
