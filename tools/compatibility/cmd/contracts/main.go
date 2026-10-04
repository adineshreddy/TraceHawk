package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	schema "github.com/santhosh-tekuri/jsonschema/v6"
	"os"
	"path/filepath"
)

func decode(p string) any {
	b, e := os.ReadFile(p)
	if e != nil {
		panic(e)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if e = d.Decode(&v); e != nil {
		panic(e)
	}
	return v
}
func main() {
	root, e := filepath.Abs("../..")
	if e != nil {
		panic(e)
	}
	compiler := schema.NewCompiler()
	compiler.AssertFormat()
	paths, e := filepath.Glob(filepath.Join(root, "contracts/schemas/*.json"))
	if e != nil {
		panic(e)
	}
	compiled := map[string]*schema.Schema{}
	for _, p := range paths {
		doc := decode(p)
		id := doc.(map[string]any)["$id"].(string)
		if e = compiler.AddResource(id, doc); e != nil {
			panic(e)
		}
	}
	for _, p := range paths {
		doc := decode(p)
		s, e := compiler.Compile(doc.(map[string]any)["$id"].(string))
		if e != nil {
			panic(e)
		}
		compiled[filepath.Base(p)[:len(filepath.Base(p))-5]] = s
	}
	cases := decode(filepath.Join(root, "contracts/validation-cases.json")).([]any)
	for _, item := range cases {
		c := item.(map[string]any)
		valid := compiled[c["schema"].(string)].Validate(c["data"]) == nil
		if valid != c["valid"].(bool) {
			panic(fmt.Sprintf("case %s: got %v", c["name"], valid))
		}
	}
	report := map[string]any{"status": "passed", "schemas": len(compiled), "schema_cases": len(cases), "format_assertions": true, "library": "jsonschema/v6 v6.0.3"}
	b, e := json.MarshalIndent(report, "", "  ")
	if e != nil {
		panic(e)
	}
	if e = os.WriteFile(filepath.Join(root, "docs/evidence/contracts-go.json"), append(b, '\n'), 0644); e != nil {
		panic(e)
	}
	fmt.Println(string(b))
}
