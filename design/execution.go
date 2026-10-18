package design

import (
	. "goa.design/goa/v3/dsl"
)

// Execution management types

var ExecutionGrantPayload = Type("ExecutionGrantPayload", func() {
	Description("Signed, short-lived grant used to admit an execution request (placeholder)")
	Attribute("grant", String, "Opaque, versioned, guest-verified grant token", func() {
		MinLength(10)
		Example("eyJ2IjoiMS4wIn0....")
	})
	Attribute("os_identity", String, "Target OS identity (e.g. 'root', 'SYSTEM')", func() {
		Example("root")
	})
	Required("grant")
})

var ExecutionRecordResult = ResultType("application/vnd.execution-record+json", func() {
	Description("Execution admission record and last known outcome")
	Attributes(func() {
		Attribute("execution_id", String, "Execution identifier", func() { Example("exec_9f82") })
		Attribute("actor_id", String, "Actor identifier", func() { Example("user@example.com") })
		Attribute("operation", String, "command|script|shell", func() { Enum("command", "script", "shell"); Example("shell") })
		Attribute("namespace", String, func() { Example("team-a") })
		Attribute("workspace_name", String, func() { Example("vm-1") })
		Attribute("workspace_uid", String, func() { Example("abc123") })
		Attribute("workspace_generation", Int64, func() { Example(3) })
		Attribute("grant_version", String, func() { Example("1.0") })
		Attribute("os_identity", String, func() { Example("root") })
		Attribute("elevated", Boolean, func() { Example(false) })
		Attribute("recording_id", String, func() { Example("rec_9f82") })
		Attribute("mode", String, "Storage mode: ephemeral|external|bundled", func() { Enum("ephemeral", "external", "bundled"); Example("ephemeral") })
		Attribute("durability", String, "none|durable", func() { Enum("none", "durable"); Example("none") })
		Attribute("admitted", Boolean, func() { Example(true) })
		Attribute("admission_time", String, "RFC3339 timestamp", func() { Format(FormatDateTime); Example("2026-10-17T00:00:00Z") })
		Attribute("deny_reason", String, func() { Example("") })
		Attribute("state", String, "lifecycle state", func() {
			Enum("admitted", "running", "succeeded", "failed", "cancelled", "timed_out", "revoked", "unknown", "recording_lost")
			Example("succeeded")
		})
		Attribute("start_time", String, "RFC3339 timestamp", func() { Format(FormatDateTime) })
		Attribute("end_time", String, "RFC3339 timestamp", func() { Format(FormatDateTime) })
		Attribute("exit_code", Int, func() { Example(0) })
		Attribute("termination", String, func() { Example("graceful") })
		Attribute("recording_lost", Boolean, func() { Example(false) })
	})
	Required("execution_id", "operation", "namespace", "workspace_name", "recording_id", "mode", "durability", "admitted", "admission_time")
})

var ExecutionStatusResult = ResultType("application/vnd.execution-status+json", func() {
	Description("Execution management status")
	Attributes(func() {
		Attribute("enabled", Boolean, "Whether VM execution is enabled by policy", func() { Example(false) })
		Attribute("allow_elevated", Boolean, "Whether elevated execution is allowed by policy", func() { Example(false) })
		Attribute("storage_mode", String, "Storage mode: disabled|ephemeral|external|bundled", func() { Enum("disabled", "ephemeral", "external", "bundled"); Example("disabled") })
		Attribute("durable", Boolean, "Metadata and recordings are durable (not ephemeral)", func() { Example(false) })
		Attribute("storage_available", Boolean, "Store is Ready and can admit work", func() { Example(false) })
		Attribute("issuer_ready", Boolean, "Opt-in management issuer prerequisites and initial bootstrap sync are ready; not a guest execution capability", func() { Example(false) })
	})
	Required("enabled", "allow_elevated", "storage_mode", "durable", "storage_available", "issuer_ready")
})

var ExecutionRecordingChunk = Type("ExecutionRecordingChunk", func() {
	Description("Verified, decrypted recording chunk; sensitive playback content")
	Attribute("index", UInt64, "Chunk index starting at 0", func() { Example(0) })
	Attribute("data", Bytes, "Base64-encoded plaintext recording data")
	Required("index", "data")
})

var ExecutionRecordingManifest = Type("ExecutionRecordingManifest", func() {
	Attribute("recording_id", String)
	Attribute("chunks", UInt64)
	Attribute("plaintext_bytes", Int64)
	Attribute("verified", Boolean)
	Required("recording_id", "chunks", "plaintext_bytes", "verified")
})

var _ = Service("executions", func() {
	Description("Scoped execution management status, history and protected recording replay")
	Error("unauthorized", String, "A current user-bound credential is required")
	Error("forbidden", String, "Scoped execution permission is required")
	Error("unavailable", String, "Execution storage or policy is unavailable")
	Error("invalid", String, "Invalid management request")
	Error("not_found", String, "Execution not found")
	HTTP(func() {
		Response("unauthorized", StatusUnauthorized)
		Response("forbidden", StatusForbidden)
		Response("unavailable", StatusServiceUnavailable)
		Response("invalid", StatusBadRequest)
		Response("not_found", StatusNotFound)
	})

	Method("status", func() {
		Description("Get execution management status (policy + storage readiness)")
		Result(ExecutionStatusResult)
		HTTP(func() {
			GET("/v1/executions/status")
			Response(StatusOK)
		})
	})

	Method("list", func() {
		Description("List execution records visible to the actor")
		Payload(func() {
			Attribute("namespace", String, "Filter by namespace")
			Attribute("workspace_name", String, "Filter by workspace name")
			Attribute("actor_id", String, "Filter by actor")
			Attribute("since", String, "RFC3339 lower bound", func() { Format(FormatDateTime) })
			Attribute("limit", Int, "Max results", func() { Default(100); Minimum(1); Maximum(1000) })
		})
		Result(ArrayOf(ExecutionRecordResult))
		HTTP(func() {
			GET("/v1/executions")
			Param("namespace")
			Param("workspace_name")
			Param("actor_id")
			Param("since")
			Param("limit")
			Response(StatusOK)
		})
	})

	Method("get", func() {
		Description("Get an execution record and its last known outcome")
		Payload(func() {
			Attribute("execution_id", String, "Execution identifier", func() { Example("exec_9f82") })
			Required("execution_id")
		})
		Result(ExecutionRecordResult)
		HTTP(func() {
			GET("/v1/executions/{execution_id}")
			Response(StatusOK)
		})
	})
	Method("manifest", func() {
		Description("Verify recording integrity and audit protected playback access")
		Payload(func() { Attribute("execution_id", String); Required("execution_id") })
		Result(ExecutionRecordingManifest)
		HTTP(func() { GET("/v1/executions/{execution_id}/recording"); Response(StatusOK) })
	})
	Method("chunk", func() {
		Description("Read a verified recording chunk with fresh scoped recording-read permission")
		Payload(func() {
			Attribute("execution_id", String)
			Attribute("index", UInt64)
			Required("execution_id", "index")
		})
		Result(ExecutionRecordingChunk)
		HTTP(func() { GET("/v1/executions/{execution_id}/recording/chunks/{index}"); Response(StatusOK) })
	})
})
