package qga

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"
)

// decodeExactObject checks the complete versioned object before decoding its
// typed values. Fields are required; bool values indicate nullable fields.
// It never returns decoder errors that may contain protected guest content.
// Callers bound raw input before invoking it.
func decodeExactObject(raw []byte, result any, fields map[string]bool) bool {
	return decodeObject(raw, result, fields, nil)
}

// decodeObject also supports optional members. A nil required list requires all
// fields; a non-nil list requires only those named fields. Present non-nullable
// members must never be null, even when optional.
func decodeObject(raw []byte, result any, fields map[string]bool, required []string) bool {
	if !utf8.Valid(raw) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return false
	}
	seen := make(map[string]bool, len(fields))
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		nullable, known := fields[name]
		if err != nil || !ok || !known || seen[name] {
			return false
		}
		seen[name] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil || (!nullable && bytes.Equal(bytes.TrimSpace(value), []byte("null"))) {
			return false
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return false
	}
	if required == nil && len(seen) != len(fields) {
		return false
	}
	for _, name := range required {
		if !seen[name] {
			return false
		}
	}
	if decoder.Decode(new(any)) != io.EOF {
		return false
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(result) == nil
}

var runnerResultFields = map[string]bool{
	"version": false, "outcome": false, "exit_code": true,
	"stdout_b64": false, "stderr_b64": false, "truncated": false,
	"duration_ms": false, "denial": true,
}

var scriptCapabilityFields = map[string]bool{
	"version": false, "script_request_version": false, "interpreter_policy": false,
}
