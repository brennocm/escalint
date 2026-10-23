// Package schema embeds the JSON Schema of analysis.json (ADR 0003).
package schema

import _ "embed"

// AnalysisV1 is schema/analysis.v1.schema.json.
//
//go:embed analysis.v1.schema.json
var AnalysisV1 []byte
