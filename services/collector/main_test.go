package main

import (
	"bytes"
	"encoding/json"
	schema "github.com/santhosh-tekuri/jsonschema/v6"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestMicros(t *testing.T) {
	for raw, want := range map[string]int64{"0": 0, "0.0000005": 0, "0.0000015": 2, "0.0000025": 2, "-0.0000015": -2, "1791028801.01": 1791028801010000, "1e-6": 1} {
		got, e := micros(json.Number(raw))
		if e != nil || got != want {
			t.Fatalf("%s got %d %v want %d", raw, got, e, want)
		}
	}
	if _, e := micros("1"); e == nil {
		t.Fatal("accepted string")
	}
}
func TestMurmurVectors(t *testing.T) {
	for raw, want := range map[string]uint32{"": 275646681, "a": 2731586172, "abc": 479470107, "hello": 2132663229} {
		if got := murmur2([]byte(raw)); got != want {
			t.Fatalf("%s got %d want %d", raw, got, want)
		}
	}
}
func TestFixtureParity(t *testing.T) {
	root = filepath.Join("..", "..")
	compiler := schema.NewCompiler()
	compiler.AssertFormat()
	v, e := compiler.Compile(filepath.Join(root, "contracts/schemas/event.json"))
	if e != nil {
		t.Fatal(e)
	}
	j := Job{ScopeID: "phase0-v1", RunID: "phase0-v1", ScenarioID: "phase0-controlled-network-v1"}
	j.Meta.Folder = "scenarios/phase0"
	j.Meta.Hashes = map[string]string{}
	for _, k := range []string{"conn", "dns"} {
		b, _ := os.ReadFile(filepath.Join(root, j.Meta.Folder, "zeek", k+".log"))
		j.Meta.Hashes[k] = sha(b)
	}
	rows, e := records(j, v)
	if e != nil {
		t.Fatal(e)
	}
	if len(rows) != 108 {
		t.Fatal(len(rows))
	}
	b, _ := os.ReadFile(filepath.Join(root, j.Meta.Folder, "normalized-events.jsonl"))
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	expected := map[string]map[string]any{}
	for {
		var r map[string]any
		e := dec.Decode(&r)
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		expected[r["event_id"].(string)] = r
	}
	for _, r := range rows {
		exp := expected[r["event_id"].(string)]
		if exp == nil {
			t.Fatal("identity differs")
		}
		for _, key := range []string{"ingested_at_us", "published_at_us"} {
			delete(r, key)
			delete(exp, key)
		}
		a, _ := json.Marshal(r)
		b, _ := json.Marshal(exp)
		if !bytes.Equal(a, b) {
			t.Fatalf("normalization differs\n%s\n%s", a, b)
		}
	}
}
func TestRejectPartialAndChangedSources(t *testing.T) {
	original := root
	defer func() { root = original }()
	root = t.TempDir()
	folder := filepath.Join(root, "scenarios/phase0/zeek")
	os.MkdirAll(folder, 0755)
	j := Job{}
	j.Meta.Folder = "scenarios/phase0"
	j.Meta.Hashes = map[string]string{}
	for _, k := range []string{"conn", "dns"} {
		b := []byte(`{"ts":1}`)
		os.WriteFile(filepath.Join(folder, k+".log"), b, 0644)
		j.Meta.Hashes[k] = sha(b)
	}
	if _, e := records(j, nil); e == nil {
		t.Fatal("accepted partial record")
	}
	j.Meta.Hashes["conn"] = "wrong"
	if _, e := records(j, nil); e == nil {
		t.Fatal("accepted changed source")
	}
}
