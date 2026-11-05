// Package schema embeds the JSON Schema of the collector's detailed
// artifact, the methods of its normalized artifacts, and its trace map.
package schema

import (
	_ "embed"
	"encoding/json"
)

//go:embed v1.0.0.json
var detailed []byte

// methods is methods.json. For each normalized artifact type, it holds one
// plain sentence on how the collector measures each field.
//
//go:embed methods.json
var methods []byte

// TraceMap is the map in trace-map.json, which links each field of the
// artifacts to the calls and the code behind it, for
// componentsdk.CollectorSpec.TraceMap. `make trace-map` rewrites it.
//
//go:embed trace-map.json
var TraceMap []byte

// Schemas maps the detailed artifact's path to its JSON Schema, for
// componentsdk.CollectorSpec.Schemas. The normalized artifacts are checked
// against the SDK's own schemas for their types.
func Schemas() map[string][]byte {
	return map[string][]byte{"artifacts/jumpcloud.details.json": detailed}
}

// Methods returns the sentences in methods.json for
// componentsdk.CollectorSpec.Methods. The SDK writes each one as the
// x-epack-method of its field in the SDK's schema for the type.
func Methods() map[string]map[string]string {
	var bySchema map[string]map[string]string
	if err := json.Unmarshal(methods, &bySchema); err != nil {
		panic("docs/schema/methods.json: " + err.Error())
	}
	return bySchema
}
