package main

import (
	"encoding/json"
	"errors"
	schema "github.com/santhosh-tekuri/jsonschema/v6"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

// Local offline normalization only. Evaluation folders are never accepted by the
// production replay worker or supplied through its HTTP coordinator.
func normalizeEvaluation(jobPath, outputPath string) error {
	f, err := os.Open(jobPath)
	if err != nil {
		return err
	}
	defer f.Close()
	var job Job
	decoder := json.NewDecoder(io.LimitReader(f, 65536))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&job); err != nil {
		return err
	}
	if !regexp.MustCompile(`^evaluation/corpus/[a-z0-9-]+$`).MatchString(job.Meta.Folder) {
		return errors.New("unregistered evaluation source")
	}
	compiler := schema.NewCompiler()
	compiler.AssertFormat()
	validator, err := compiler.Compile(filepath.Join(root, "contracts/schemas/event.json"))
	if err != nil {
		return err
	}
	events, err := recordsWithEvaluation(job, validator, true)
	if err != nil {
		return err
	}
	out, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer out.Close()
	partitions := map[string]int32{}
	for _, event := range events {
		partitions[event["source_ip"].(string)] = partition(job.ScopeID, event["source_ip"].(string))
		// Fixture times are deterministic and explicitly differ from live replay.
		event["ingested_at_us"], event["published_at_us"] = job.Meta.End+120000000, job.Meta.End+120001000
		if err = json.NewEncoder(out).Encode(event); err != nil {
			return err
		}
	}
	b, err := json.Marshal(partitions)
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath+".partitions.json", b, 0600)
}
