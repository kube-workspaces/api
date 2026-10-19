package design

import (
	. "goa.design/goa/v3/dsl"
)

// AgentUpgradeAttemptResult is the protected metadata/progress/outcome for one
// admitted agent upgrade attempt.
var AgentUpgradeAttemptResult = ResultType("application/vnd.agent-upgrade-attempt+json", func() {
	Description("Admitted agent upgrade attempt with phase progress and outcome")
	Attributes(func() {
		Attribute("attempt_id", String, "Server-minted attempt identifier", func() {
			Pattern(`^upg_[0-9a-f]{24}$`)
			Example("upg_9f82c1a0b3d4e5f60718293a")
		})
		Attribute("namespace", String, func() { Example("team-a") })
		Attribute("workspace_name", String, func() { Example("vm-1") })
		Attribute("workspace_uid", String, func() { Example("abc123") })
		Attribute("vm_uid", String, "Controller-owned VM UID the reservation is bound to", func() {
			Example("0d3f9a7e-6b1c-4f2a-9e8d-1a2b3c4d5e6f")
		})
		Attribute("actor_id", String, "UID of the administrator that admitted the attempt", func() { Example("user-uid-1") })
		Attribute("state", String, "Attempt lifecycle state", func() {
			Enum(
				"admitted", "staging", "prepared", "installing", "verifying", "succeeded",
				"awaiting_reboot", "rollback_pending", "rolling_back", "rolled_back",
				"cancelled", "failed", "manual_recovery_required", "unknown", "recording_lost",
			)
			Example("admitted")
		})
		Attribute("target_id", String, func() { Example("windows11-amd64-v2") })
		Attribute("target_manifest_sha256", String, func() {
			Pattern(`^[0-9a-f]{64}$`)
			Example("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
		})
		Attribute("expected_installed_inventory_sha256", String, func() {
			Pattern(`^[0-9a-f]{64}$`)
			Example("810151abf0615815b24e01967ec665e0eb583500f1eb5fa456361935b22b183b")
		})
		Attribute("allow_reboot", Boolean, "Whether the admitted attempt may run the bounded reboot sequence", func() { Example(false) })
		Attribute("cancel_requested", Boolean, "An administrator requested safe-boundary cancellation", func() { Example(false) })
		Attribute("execution_id", String, "Linked execution admission record (recording authorization)", func() {
			Example("exec_9f82")
		})
		Attribute("recording_id", String, "Protected attempt recording", func() { Example("rec_9f82") })
		Attribute("recording_url", String, "Independently authorized recording link", func() {
			Example("/v1/executions/exec_9f82/recording")
		})
		Attribute("status_url", String, "Canonical status URL for this attempt", func() {
			Example("/v1/workspaces/vm-1/agent-upgrades/upg_9f82c1a0b3d4e5f60718293a?namespace=team-a")
		})
		Attribute("journal_sequence", UInt64, "Last reconciled guest journal sequence", func() { Example(0) })
		Attribute("predecessor_target_id", String, "Pinned rollback predecessor target", func() { Example("windows11-amd64-v1") })
		Attribute("predecessor_manifest_sha256", String, "Pinned rollback predecessor manifest digest", func() {
			Pattern(`^[0-9a-f]{64}$`)
		})
		Attribute("error_code", String, "Bounded machine-readable failure code", func() { Example("") })
		Attribute("admitted_at", String, "RFC3339 admission timestamp", func() {
			Format(FormatDateTime)
			Example("2026-10-19T00:00:00Z")
		})
		Attribute("staging_at", String, func() { Format(FormatDateTime) })
		Attribute("prepared_at", String, func() { Format(FormatDateTime) })
		Attribute("installing_at", String, func() { Format(FormatDateTime) })
		Attribute("awaiting_reboot_at", String, func() { Format(FormatDateTime) })
		Attribute("verifying_at", String, func() { Format(FormatDateTime) })
		Attribute("rollback_requested_at", String, func() { Format(FormatDateTime) })
		Attribute("rolling_back_at", String, func() { Format(FormatDateTime) })
		Attribute("terminal_at", String, func() { Format(FormatDateTime) })
		Attribute("updated_at", String, func() { Format(FormatDateTime) })
	})
	Required(
		"attempt_id", "namespace", "workspace_name", "workspace_uid", "vm_uid", "actor_id",
		"state", "target_id", "target_manifest_sha256", "expected_installed_inventory_sha256",
		"allow_reboot", "cancel_requested", "execution_id", "recording_id", "recording_url",
		"status_url", "journal_sequence", "admitted_at", "updated_at",
	)
})

// AgentUpgradeAvailability reports whether a start would be admissible right
// now, with a single machine-readable deny reason.
var AgentUpgradeAvailability = ResultType("application/vnd.agent-upgrade-availability+json", func() {
	Description("Fresh agent-upgrade availability for one workspace")
	Attributes(func() {
		Attribute("policy_enabled", Boolean, "Platform policy admits agent upgrades", func() { Example(false) })
		Attribute("storage_available", Boolean, "Durable attempt/recording storage is ready", func() { Example(false) })
		Attribute("workspace_eligible", Boolean, "Workspace resolves as an eligible running Windows VM", func() { Example(false) })
		Attribute("inventory_available", Boolean, "Fresh authenticated guest inventory is available (guest integration)", func() {
			Example(false)
		})
		Attribute("admissible", Boolean, "A start request would be admitted right now", func() { Example(false) })
		Attribute("deny_reason", String, "Why start would be denied; empty when admissible", func() {
			Enum("", "policy_disabled", "storage_unavailable", "eligibility_unavailable", "workspace_not_eligible", "attempt_active")
			Example("policy_disabled")
		})
		Attribute("active_attempt_id", String, "Reservation-holding attempt for this VM, when present", func() {
			Example("upg_9f82c1a0b3d4e5f60718293a")
		})
		Attribute("vm_uid", String, "Resolved controller-owned VM UID, when eligible", func() {
			Example("0d3f9a7e-6b1c-4f2a-9e8d-1a2b3c4d5e6f")
		})
	})
	Required("policy_enabled", "storage_available", "workspace_eligible", "inventory_available", "admissible", "deny_reason")
})

var AgentUpgradeStartPayload = Type("AgentUpgradeStartPayload", func() {
	Description("Admit a single explicit agent upgrade. Clients cannot submit URLs, hashes of payloads, install directories or installer flags.")
	Attribute("namespace", String, func() {
		Pattern("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
		MaxLength(63)
		Default("workspaces")
		Example("team-a")
	})
	Attribute("name", String, func() {
		Pattern("^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$")
		MaxLength(253)
		Example("vm-1")
	})
	Attribute("target_id", String, "Operator-approved immutable target", func() {
		Pattern(`^[a-z0-9][a-z0-9._-]{0,127}$`)
		Example("windows11-amd64-v2")
	})
	Attribute("target_manifest_sha256", String, "Expected signed manifest digest for the target", func() {
		Pattern(`^[0-9a-f]{64}$`)
		Example("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	})
	Attribute("expected_vm_uid", String, "Client-observed VM UID; must match the current controller-owned UID", func() {
		Pattern(`^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$`)
		Example("0d3f9a7e-6b1c-4f2a-9e8d-1a2b3c4d5e6f")
	})
	Attribute("expected_revocation_epoch", UInt64, "Client-observed execution revocation epoch", func() { Example(4) })
	Attribute("expected_installed_inventory_sha256", String, "Client-observed installed inventory digest (re-verified before install)", func() {
		Pattern(`^[0-9a-f]{64}$`)
		Example("810151abf0615815b24e01967ec665e0eb583500f1eb5fa456361935b22b183b")
	})
	Attribute("idempotency_key", String, "Client-chosen key; an identical replay returns the original attempt", func() {
		Pattern(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
		Example("run-2026-10-19-001")
	})
	Attribute("allow_reboot", Boolean, "Permit the recorded bounded reboot sequence", func() {
		Default(false)
		Example(false)
	})
	Required(
		"namespace", "name", "target_id", "target_manifest_sha256", "expected_vm_uid",
		"expected_revocation_epoch", "expected_installed_inventory_sha256", "idempotency_key", "allow_reboot",
	)
})

var _ = Service("agentupgrades", func() {
	Description("Administrator-only agent upgrade admission: availability, start, status, cancel and rollback")
	Error("unauthorized", String, "A current UID-bound credential is required")
	Error("forbidden", String, "Administrator access and platform policy are required")
	Error("invalid", String, "Invalid upgrade request")
	Error("not_found", String, "Attempt not found")
	Error("conflict", String, "A conflicting attempt, reservation or state prevents the request")
	Error("unavailable", String, "Upgrade storage or platform policy is unavailable")
	HTTP(func() {
		Response("unauthorized", StatusUnauthorized)
		Response("forbidden", StatusForbidden)
		Response("invalid", StatusBadRequest)
		Response("not_found", StatusNotFound)
		Response("conflict", StatusConflict)
		Response("unavailable", StatusServiceUnavailable)
	})

	Method("availability", func() {
		Description("Fresh availability for one workspace; administrative access required")
		Payload(func() {
			Attribute("namespace", String, func() { Default("workspaces") })
			Attribute("name", String)
			Required("name")
		})
		Result(AgentUpgradeAvailability)
		HTTP(func() {
			GET("/v1/workspaces/{name}/agent-upgrades/availability")
			Param("namespace")
			Response(StatusOK)
		})
	})

	Method("start", func() {
		Description("Admit a single explicit upgrade; returns 202 with the durable attempt identity")
		Payload(AgentUpgradeStartPayload)
		Result(AgentUpgradeAttemptResult)
		HTTP(func() {
			POST("/v1/workspaces/{name}/agent-upgrades")
			Param("namespace")
			Response(StatusAccepted)
		})
	})

	Method("status", func() {
		Description("Protected attempt metadata/progress/outcome and independently authorized recording links")
		Payload(func() {
			Attribute("namespace", String, func() { Default("workspaces") })
			Attribute("name", String)
			Attribute("attempt_id", String, func() { Pattern(`^upg_[0-9a-f]{24}$`) })
			Required("name", "attempt_id")
		})
		Result(AgentUpgradeAttemptResult)
		HTTP(func() {
			GET("/v1/workspaces/{name}/agent-upgrades/{attempt_id}")
			Param("namespace")
			Response(StatusOK)
		})
	})

	Method("cancel", func() {
		Description("Request safe cancellation; never promises to kill an active MSI transaction")
		Payload(func() {
			Attribute("namespace", String, func() { Default("workspaces") })
			Attribute("name", String)
			Attribute("attempt_id", String, func() { Pattern(`^upg_[0-9a-f]{24}$`) })
			Required("name", "attempt_id")
		})
		Result(AgentUpgradeAttemptResult)
		HTTP(func() {
			POST("/v1/workspaces/{name}/agent-upgrades/{attempt_id}/cancel")
			Param("namespace")
			Response(StatusOK)
		})
	})

	Method("rollback", func() {
		Description("Admit a separate, explicit rollback to that attempt's pinned previous payload")
		Payload(func() {
			Attribute("namespace", String, func() { Default("workspaces") })
			Attribute("name", String)
			Attribute("attempt_id", String, func() { Pattern(`^upg_[0-9a-f]{24}$`) })
			Required("name", "attempt_id")
		})
		Result(AgentUpgradeAttemptResult)
		HTTP(func() {
			POST("/v1/workspaces/{name}/agent-upgrades/{attempt_id}/rollback")
			Param("namespace")
			Response(StatusAccepted)
		})
	})
})
