package design

import (
	. "goa.design/goa/v3/dsl"
)

var _ = API("kube-workspaces", func() {
	Title("Kube Workspaces API")
	Description("API for managing container-based workspaces in Kubernetes")
	Version("1.0.0")
	Server("kube-workspaces", func() {
		Host("localhost", func() {
			URI("http://localhost:8080")
		})
	})
})

// Workspace types

var WorkspaceContainer = Type("WorkspaceContainer", func() {
	Description("Container specification for a workspace")
	Attribute("name", String, "Container name", func() {
		Example("code-server")
	})
	Attribute("image", String, "Container image", func() {
		Example("codercom/code-server:latest")
	})
	Attribute("port", Int, "Container port", func() {
		Default(8080)
		Example(8080)
	})
	Attribute("cpu_request", String, "CPU request", func() {
		Default("500m")
		Example("500m")
	})
	Attribute("memory_request", String, "Memory request", func() {
		Default("512Mi")
		Example("512Mi")
	})
	Attribute("cpu_limit", String, "CPU limit", func() {
		Default("2")
		Example("2")
	})
	Attribute("memory_limit", String, "Memory limit", func() {
		Default("2Gi")
		Example("2Gi")
	})
	Attribute("gpu_request", String, "GPU resource request count (e.g. \"1\")", func() {
		Example("1")
	})
	Attribute("gpu_vendor", String, "GPU vendor resource name (e.g. nvidia.com/gpu, amd.com/gpu)", func() {
		Default("nvidia.com/gpu")
		Example("nvidia.com/gpu")
	})
	Required("name", "image")
})

var Toleration = Type("Toleration", func() {
	Description("Kubernetes pod toleration")
	Attribute("key", String, "Toleration key", func() {
		Example("nvidia.com/gpu")
	})
	Attribute("operator", String, "Operator: Exists or Equal", func() {
		Enum("Exists", "Equal")
		Default("Equal")
		Example("Equal")
	})
	Attribute("value", String, "Toleration value", func() {
		Example("true")
	})
	Attribute("effect", String, "Taint effect: NoSchedule, PreferNoSchedule, or NoExecute", func() {
		Enum("NoSchedule", "PreferNoSchedule", "NoExecute", "")
		Example("NoSchedule")
	})
	Required("key")
})

var EnvVar = Type("EnvVar", func() {
	Description("Custom environment variable for a workspace")
	Attribute("name", String, "Environment variable name", func() {
		Example("MY_VAR")
	})
	Attribute("value", String, "Environment variable value", func() {
		Example("my-value")
	})
	Required("name", "value")
})

var VolumeMount = Type("VolumeMount", func() {
	Description("Volume mount for a workspace container")
	Attribute("name", String, "Volume/PVC name", func() {
		Example("my-workspace-data")
	})
	Attribute("mount_path", String, "Mount path in container", func() {
		Example("/home/coder")
	})
	Required("name", "mount_path")
})

var CreateWorkspacePayload = Type("CreateWorkspacePayload", func() {
	Description("Payload for creating a new workspace")
	Attribute("name", String, "Workspace name", func() {
		Pattern(`^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$`)
		MaxLength(63)
		Example("my-workspace")
	})
	Attribute("namespace", String, "Target namespace", func() {
		Default("workspaces")
		Example("workspaces")
	})
	Attribute("type", String, "Workspace type: 'container' (default, runs as a StatefulSet), 'vm' (KubeVirt VirtualMachine booting a containerDisk image), or 'scratch' (plain Deployment)", func() {
		Enum("container", "vm", "scratch")
		Default("container")
		Example("container")
	})
	Attribute("container", WorkspaceContainer, "Main container spec")
	Attribute("volume_mounts", ArrayOf(VolumeMount), "Volumes to mount", func() {
		Example([]map[string]interface{}{{"name": "my-workspace-data", "mount_path": "/home/coder"}})
	})
	Attribute("env", ArrayOf(EnvVar), "Custom environment variables to inject into the workspace container", func() {
		Example([]map[string]interface{}{{"name": "PASSWORD", "value": "changeme"}})
	})
	Attribute("tolerations", ArrayOf(Toleration), "Pod tolerations for scheduling", func() {
		Example([]map[string]interface{}{{"key": "nvidia.com/gpu", "operator": "Equal", "value": "true", "effect": "NoSchedule"}})
	})
	Attribute("node_selector", MapOf(String, String), "Node selector labels for scheduling", func() {
		Example(map[string]string{"nvidia.com/gpu": "true"})
	})
	Attribute("shared_memory", Boolean, "Mount /dev/shm as an emptyDir with medium=Memory (required for Chrome, ML frameworks)", func() {
		Default(false)
		Example(true)
	})
	Attribute("image_pull_policy", String, "Image pull policy for the workspace container (Always, IfNotPresent, Never)", func() {
		Enum("Always", "IfNotPresent", "Never")
		Default("IfNotPresent")
		Example("IfNotPresent")
	})
	Required("name", "container")
})

var WorkspaceCondition = Type("WorkspaceCondition", func() {
	Description("Condition of a workspace")
	Attribute("type", String, "Condition type", func() {
		Example("Ready")
	})
	Attribute("status", String, "Condition status", func() {
		Example("True")
	})
	Attribute("reason", String, "Brief reason", func() {
		Example("MinimumReplicasAvailable")
	})
	Attribute("message", String, "Detailed message", func() {
		Example("StatefulSet my-workspace is available")
	})
	Attribute("last_transition_time", String, "Last transition time", func() {
		Example("2025-01-02T15:04:05Z")
	})
})

var ContainerState = Type("ContainerState", func() {
	Description("State of the workspace container")
	Attribute("state", String, "Current state: running, waiting, terminated", func() {
		Enum("running", "waiting", "terminated", "unknown")
		Example("running")
	})
	Attribute("reason", String, "Reason for the state", func() {
		Example("Started")
	})
	Attribute("message", String, "Details about the state", func() {
		Example("Container started successfully")
	})
	Attribute("started_at", String, "Time the container started", func() {
		Example("2025-01-02T15:04:05Z")
	})
})

var WorkspaceResult = ResultType("application/vnd.workspace+json", func() {
	Description("A workspace resource")
	Attributes(func() {
		Attribute("name", String, "Workspace name", func() {
			Example("my-workspace")
		})
		Attribute("namespace", String, "Kubernetes namespace", func() {
			Example("workspaces")
		})
		Attribute("type", String, "Workspace type: container, vm, or scratch", func() {
			Enum("container", "vm", "scratch")
			Default("container")
			Example("container")
		})
		Attribute("image", String, "Container image", func() {
			Example("codercom/code-server:latest")
		})
		Attribute("port", Int, "Container port", func() {
			Example(8080)
		})
		Attribute("cpu_request", String, "CPU request", func() {
			Example("500m")
		})
		Attribute("memory_request", String, "Memory request", func() {
			Example("512Mi")
		})
		Attribute("cpu_limit", String, "CPU limit", func() {
			Example("1")
		})
		Attribute("memory_limit", String, "Memory limit", func() {
			Example("2Gi")
		})
		Attribute("ready_replicas", Int, "Number of ready replicas", func() {
			Example(1)
		})
		Attribute("container_state", ContainerState, "Container state")
		Attribute("conditions", ArrayOf(WorkspaceCondition), "Workspace conditions", func() {
			Example([]map[string]interface{}{{
				"type":                 "Ready",
				"status":               "True",
				"reason":               "MinimumReplicasAvailable",
				"message":              "StatefulSet my-workspace is available",
				"last_transition_time": "2025-01-02T15:04:05Z",
			}})
		})
		Attribute("stopped", Boolean, "Whether the workspace is stopped", func() {
			Example(false)
		})
		Attribute("created_at", String, "Creation timestamp", func() {
			Example("2025-01-02T15:04:05Z")
		})
		Attribute("volume_mounts", ArrayOf(VolumeMount), "Attached volumes", func() {
			Example([]map[string]interface{}{{"name": "my-workspace-data", "mount_path": "/home/coder"}})
		})
	})
	Required("name", "namespace", "image", "type", "ready_replicas", "stopped")
})

// Volume types

var CreateVolumePayload = Type("CreateVolumePayload", func() {
	Description("Payload for creating a new PVC")
	Attribute("name", String, "PVC name", func() {
		Pattern(`^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$`)
		MaxLength(63)
		Example("my-data")
	})
	Attribute("namespace", String, "Target namespace", func() {
		Default("workspaces")
		Example("workspaces")
	})
	Attribute("size", String, "Storage size", func() {
		Default("5Gi")
		Example("10Gi")
	})
	Attribute("storage_class", String, "Storage class name", func() {
		Example("standard")
	})
	Attribute("access_mode", String, "Access mode", func() {
		Default("ReadWriteOnce")
		Enum("ReadWriteOnce", "ReadWriteMany", "ReadOnlyMany")
		Example("ReadWriteOnce")
	})
	Required("name", "size")
})

var VolumeResult = ResultType("application/vnd.volume+json", func() {
	Description("A persistent volume claim")
	Attributes(func() {
		Attribute("name", String, "PVC name", func() {
			Example("my-workspace-data")
		})
		Attribute("namespace", String, "Kubernetes namespace", func() {
			Example("workspaces")
		})
		Attribute("size", String, "Storage size", func() {
			Example("10Gi")
		})
		Attribute("storage_class", String, "Storage class", func() {
			Example("standard")
		})
		Attribute("access_mode", String, "Access mode", func() {
			Example("ReadWriteOnce")
		})
		Attribute("phase", String, "PVC phase (Bound, Pending, etc.)", func() {
			Example("Bound")
		})
		Attribute("created_at", String, "Creation timestamp", func() {
			Example("2025-01-02T15:04:05Z")
		})
		Attribute("labels", MapOf(String, String), "Kubernetes labels on the PVC", func() {
			Example(map[string]string{"managed-by": "kube-workspaces", "workspace": "my-workspace"})
		})
	})
	Required("name", "namespace", "size", "phase")
})

// Image types

var CreateImagePayload = Type("CreateImagePayload", func() {
	Description("Payload for creating a new image")
	Attribute("name", String, "Display name", func() {
		Example("Code Server (VS Code)")
	})
	Attribute("image", String, "Container image reference", func() {
		Example("codercom/code-server:latest")
	})
	Attribute("description", String, "Description of the image", func() {
		Example("Code editor in the browser")
	})
	Attribute("category", String, "Category for grouping (e.g. Desktop, IDE, Tool, Game)", func() {
		Example("IDE")
	})
	Attribute("tags", ArrayOf(String), "Tags for filtering/searching images", func() {
		Example([]string{"development", "vscode"})
	})
	Attribute("default_port", Int, "Default container port", func() {
		Example(8080)
	})
	Attribute("default_path", String, "Default URL path for connecting", func() {
		Example("/")
	})
	Attribute("icon", String, "Icon identifier", func() {
		Example("code")
	})
	Attribute("default_args", ArrayOf(String), "Default command-line args", func() {
		Example([]string{"--bind-addr", "0.0.0.0:8080"})
	})
	Attribute("default_env", ArrayOf(ImageEnvVar), "Default environment variables", func() {
		Example([]map[string]interface{}{{"name": "PASSWORD", "value": "changeme"}})
	})
	Attribute("privileged", Boolean, "Run container in privileged mode", func() {
		Default(false)
		Example(false)
	})
	Attribute("homepage_url", String, "Project homepage or documentation URL", func() {
		Example("https://github.com/coder/code-server")
	})
	Attribute("source_url", String, "Source code repository URL", func() {
		Example("https://github.com/coder/code-server")
	})
	Attribute("image_homepage_url", String, "Container image registry page (e.g. Docker Hub)", func() {
		Example("https://hub.docker.com/r/codercom/code-server")
	})
	Attribute("default_user", String, "Default user for this image", func() {
		Example("coder")
	})
	Attribute("default_password", String, "Known default password for DefaultUser. Only set when the image has a known default password; leave unset when the guest uses no password", func() {
		Example("changeme")
	})
	Attribute("default_cloud_init", Boolean, "Set to true when the image has cloud-init baked in, allowing user-data (e.g. a user/password) to be seeded into the guest at first boot", func() {
		Example(false)
	})
	Attribute("default_user_data", String, "Reserved user-data for the guest (cloud-init). Empty by default; later used to seed first-boot configuration when cloud-init is supported. Not yet consumed", func() {
		Example("")
	})
	Attribute("default_homedir", String, "Default home directory for the default user", func() {
		Example("/home/coder")
	})
	Attribute("default_shell", String, "Default shell for exec/console sessions (e.g. /bin/bash)", func() {
		Example("/bin/bash")
	})
	Attribute("links", ArrayOf(ImageLink), "Additional relevant URLs for this image", func() {
		Example([]map[string]interface{}{{"title": "GitHub", "url": "https://github.com/coder/code-server"}, {"title": "Docker Hub", "url": "https://hub.docker.com/r/codercom/code-server"}})
	})
	Attribute("default_credentials", ImageCredentials, "Default login credentials for this image")
	Attribute("proxy_config", ImageProxyConfig, "Proxy behavior configuration")
	Attribute("default_uid", Int64, "UID that the main container runs as (sets runAsUser and fsGroup)", func() {
		Example(1000)
	})
	Attribute("default_shared_memory", Boolean, "Automatically mount /dev/shm as emptyDir with medium=Memory (required for Selkies streaming, Chrome, ML frameworks)", func() {
		Example(false)
	})
	Attribute("workspace_types", ArrayOf(String), "Workspace types this image supports (container, vm, scratch). Empty means container-only", func() {
		Example([]string{"container"})
	})
	Required("name", "image", "default_port")
})

var ImageEnvVar = Type("ImageEnvVar", func() {
	Description("Environment variable with optional placeholder support")
	Attribute("name", String, "Name of the environment variable", func() {
		Example("PASSWORD")
	})
	Attribute("value", String, "Value (supports {{namespace}} and {{name}} placeholders)", func() {
		Example("changeme")
	})
	Required("name", "value")
})

var ImageLink = Type("ImageLink", func() {
	Description("A named URL link for an image")
	Attribute("title", String, "Display label for the link", func() {
		Example("GitHub")
	})
	Attribute("url", String, "Link target URL", func() {
		Example("https://github.com/coder/code-server")
	})
	Required("title", "url")
})

var ImageCredentials = Type("ImageCredentials", func() {
	Description("Default login credentials for a workspace image")
	Attribute("username", String, "Default username", func() {
		Example("coder")
	})
	Attribute("password", String, "Default password", func() {
		Example("changeme")
	})
})

var ImageProxyConfig = Type("ImageProxyConfig", func() {
	Description("Proxy configuration hints for a workspace image")
	Attribute("needs_noop_sw", Boolean, "Serve a no-op ServiceWorker at /sw.js to prevent SW registration errors", func() {
		Default(false)
	})
	Attribute("websocket_paths", ArrayOf(String), "Paths that use WebSocket (informational, all paths support WS transparently)", func() {
		Example([]string{"/websockify"})
	})
	Attribute("rewrite_host_absolute_paths", Boolean, "Rewrite requests with absolute paths that escape the proxy prefix using Referer header", func() {
		Default(false)
	})
	Attribute("custom_request_headers", MapOf(String, String), "Additional headers to inject into proxied requests", func() {
		Example(map[string]string{"x-tenant": "workspaces"})
	})
	Attribute("inject_base_tag", Boolean, "Inject a <base> tag into HTML responses to fix relative path resolution", func() {
		Default(false)
	})
	Attribute("tls_insecure", Boolean, "Connect to backend over HTTPS with skip-verify (for self-signed certs)", func() {
		Default(false)
	})
	Attribute("preserve_path_prefix", Boolean, "Forward the full proxy path (including /proxy/{ns}/{name}) to the pod instead of stripping it. Required for apps configured with a base URL matching the proxy prefix.", func() {
		Default(false)
	})
})

var ImageResult = ResultType("application/vnd.image+json", func() {
	Description("An available workspace image")
	Attributes(func() {
		Attribute("cr_name", String, "Kubernetes resource name (metadata.name)", func() {
			Example("code-server")
		})
		Attribute("name", String, "Display name", func() {
			Example("Code Server (VS Code)")
		})
		Attribute("image", String, "Full image reference", func() {
			Example("codercom/code-server:latest")
		})
		Attribute("description", String, "Description of the image", func() {
			Example("Code editor in the browser")
		})
		Attribute("category", String, "Category for grouping (e.g. Desktop, IDE, Tool, Game)", func() {
			Example("IDE")
		})
		Attribute("tags", ArrayOf(String), "Tags for filtering/searching images", func() {
			Example([]string{"development", "vscode"})
		})
		Attribute("default_port", Int, "Default container port", func() {
			Example(8080)
		})
		Attribute("default_path", String, "Default URL path for connecting (e.g. /vnc.html?resize=remote)", func() {
			Example("/")
		})
		Attribute("proxy_config", ImageProxyConfig, "Proxy behavior configuration for this image")
		Attribute("icon", String, "Icon identifier", func() {
			Example("code")
		})
		Attribute("default_args", ArrayOf(String), "Default command-line args injected at workspace creation", func() {
			Example([]string{"--bind-addr", "0.0.0.0:8080"})
		})
		Attribute("default_env", ArrayOf(ImageEnvVar), "Default environment variables injected at workspace creation", func() {
			Example([]map[string]interface{}{{"name": "PASSWORD", "value": "changeme"}})
		})
		Attribute("default_uid", Int64, "UID that the main container runs as (sets runAsUser and fsGroup)", func() {
			Example(1000)
		})
		Attribute("default_shared_memory", Boolean, "Automatically mount /dev/shm as emptyDir with medium=Memory (required for Selkies streaming, Chrome, ML frameworks)", func() {
			Example(false)
		})
		Attribute("privileged", Boolean, "Run container in privileged mode", func() {
			Example(false)
		})
		Attribute("homepage_url", String, "Project homepage or documentation URL", func() {
			Example("https://github.com/coder/code-server")
		})
		Attribute("source_url", String, "Source code repository URL", func() {
			Example("https://github.com/coder/code-server")
		})
		Attribute("image_homepage_url", String, "Container image registry page (e.g. Docker Hub)", func() {
			Example("https://hub.docker.com/r/codercom/code-server")
		})
		Attribute("default_user", String, "Default user for this image", func() {
			Example("coder")
		})
		Attribute("default_password", String, "Known default password for DefaultUser. Only set when the image has a known default password; leave unset when the guest uses no password", func() {
			Example("changeme")
		})
		Attribute("default_cloud_init", Boolean, "Set to true when the image has cloud-init baked in, allowing user-data (e.g. a user/password) to be seeded into the guest at first boot", func() {
			Example(false)
		})
		Attribute("default_user_data", String, "Reserved user-data for the guest (cloud-init). Empty by default; later used to seed first-boot configuration when cloud-init is supported. Not yet consumed", func() {
			Example("")
		})
		Attribute("default_homedir", String, "Default home directory for the default user", func() {
			Example("/home/coder")
		})
		Attribute("default_shell", String, "Default shell for exec/console sessions (e.g. /bin/bash)", func() {
			Example("/bin/bash")
		})
		Attribute("links", ArrayOf(ImageLink), "Additional relevant URLs for this image", func() {
			Example([]map[string]interface{}{{"title": "GitHub", "url": "https://github.com/coder/code-server"}, {"title": "Docker Hub", "url": "https://hub.docker.com/r/codercom/code-server"}})
		})
		Attribute("default_credentials", ImageCredentials, "Default login credentials for this image")
		Attribute("workspace_types", ArrayOf(String), "Workspace types this image supports (container, vm, scratch). Empty means container-only", func() {
			Example([]string{"container"})
		})
	})
	Required("cr_name", "name", "image", "default_port")
})

// Namespace types

var NamespaceResult = ResultType("application/vnd.namespace+json", func() {
	Description("A Kubernetes namespace")
	Attributes(func() {
		Attribute("name", String, "Namespace name", func() {
			Example("workspaces")
		})
		Attribute("phase", String, "Namespace phase", func() {
			Example("Active")
		})
		Attribute("created_at", String, "Creation timestamp", func() {
			Example("2025-01-02T15:04:05Z")
		})
	})
	Required("name", "phase")
})

// SSH key types

var CreateSshKeyPayload = Type("CreateSshKeyPayload", func() {
	Description("Payload for storing a user's SSH public key")
	Attribute("name", String, "Resource name for the SshKey CR", func() {
		Pattern(`^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$`)
		MaxLength(63)
		Example("laptop-2025")
	})
	Attribute("namespace", String, "Target namespace (defaults to the user's personal namespace)", func() {
		Example("chris-at-fordham-id-au")
	})
	Attribute("key_name", String, "Human-friendly label for the key", func() {
		Example("Laptop 2025")
	})
	Attribute("public_key", String, "SSH public key line (e.g. ssh-ed25519 AAAA... user@host)", func() {
		Example("ssh-ed25519 AAAA... user@host")
	})
	Required("name", "public_key")
})

var SshKeyResult = ResultType("application/vnd.sshkey+json", func() {
	Description("A stored SSH public key")
	Attributes(func() {
		Attribute("name", String, "Resource name of the SshKey CR", func() {
			Example("laptop-2025")
		})
		Attribute("namespace", String, "Kubernetes namespace", func() {
			Example("chris-at-fordham-id-au")
		})
		Attribute("key_name", String, "Human-friendly label", func() {
			Example("Laptop 2025")
		})
		Attribute("public_key", String, "SSH public key line", func() {
			Example("ssh-rsa AAAAB3Nza... user@example.com")
		})
		Attribute("fingerprint", String, "SHA256 fingerprint of the key", func() {
			Example("SHA256:aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789")
		})
		Attribute("created_at", String, "Creation timestamp", func() {
			Example("2025-01-02T15:04:05Z")
		})
	})
	Required("name", "namespace", "public_key")
})

// Service definitions

var _ = Service("workspaces", func() {
	Description("Workspace management service")

	Method("list", func() {
		Description("List all workspaces")
		Payload(func() {
			Attribute("namespace", String, "Filter by namespace", func() {
				Default("workspaces")
				Example("workspaces")
			})
		})
		Result(ArrayOf(WorkspaceResult))
		HTTP(func() {
			GET("/v1/workspaces")
			Param("namespace")
			Response(StatusOK)
		})
	})

	Method("get", func() {
		Description("Get a workspace by name")
		Payload(func() {
			Attribute("namespace", String, "Namespace", func() {
				Default("workspaces")
				Example("workspaces")
			})
			Attribute("name", String, "Workspace name", func() {
				Example("my-workspace")
			})
			Required("name")
		})
		Result(WorkspaceResult)
		Error("not_found", String, "Workspace not found", func() {
			Example("workspace \"my-workspace\" not found")
		})
		HTTP(func() {
			GET("/v1/workspaces/{name}")
			Param("namespace")
			Response(StatusOK)
			Response("not_found", StatusNotFound)
		})
	})

	Method("create", func() {
		Description("Create a new workspace")
		Payload(CreateWorkspacePayload)
		Result(WorkspaceResult)
		Error("already_exists", String, "Workspace already exists", func() {
			Example("workspace \"my-workspace\" already exists")
		})
		Error("invalid", String, "Invalid workspace specification", func() {
			Example("container.image must be a valid container image")
		})
		HTTP(func() {
			POST("/v1/workspaces")
			Response(StatusCreated)
			Response("already_exists", StatusConflict)
			Response("invalid", StatusBadRequest)
		})
	})

	Method("delete", func() {
		Description("Delete a workspace")
		Payload(func() {
			Attribute("namespace", String, "Namespace", func() {
				Default("workspaces")
				Example("workspaces")
			})
			Attribute("name", String, "Workspace name", func() {
				Example("my-workspace")
			})
			Required("name")
		})
		Error("not_found", String, "Workspace not found", func() {
			Example("workspace \"my-workspace\" not found")
		})
		HTTP(func() {
			DELETE("/v1/workspaces/{name}")
			Param("namespace")
			Response(StatusNoContent)
			Response("not_found", StatusNotFound)
		})
	})

	Method("start", func() {
		Description("Start a stopped workspace")
		Payload(func() {
			Attribute("namespace", String, "Namespace", func() {
				Default("workspaces")
				Example("workspaces")
			})
			Attribute("name", String, "Workspace name", func() {
				Example("my-workspace")
			})
			Required("name")
		})
		Result(WorkspaceResult)
		Error("not_found", String, "Workspace not found", func() {
			Example("workspace \"my-workspace\" not found")
		})
		HTTP(func() {
			POST("/v1/workspaces/{name}/start")
			Param("namespace")
			Response(StatusOK)
			Response("not_found", StatusNotFound)
		})
	})

	Method("stop", func() {
		Description("Stop a running workspace")
		Payload(func() {
			Attribute("namespace", String, "Namespace", func() {
				Default("workspaces")
				Example("workspaces")
			})
			Attribute("name", String, "Workspace name", func() {
				Example("my-workspace")
			})
			Required("name")
		})
		Result(WorkspaceResult)
		Error("not_found", String, "Workspace not found", func() {
			Example("workspace \"my-workspace\" not found")
		})
		HTTP(func() {
			POST("/v1/workspaces/{name}/stop")
			Param("namespace")
			Response(StatusOK)
			Response("not_found", StatusNotFound)
		})
	})

	Method("reset", func() {
		Description("Reset a workspace by re-provisioning it from its image")
		Payload(func() {
			Attribute("namespace", String, "Namespace", func() {
				Default("workspaces")
				Example("workspaces")
			})
			Attribute("name", String, "Workspace name", func() {
				Example("my-workspace")
			})
			Required("name")
		})
		Result(WorkspaceResult)
		Error("not_found", String, "Workspace not found", func() {
			Example("workspace \"my-workspace\" not found")
		})
		Error("invalid", String, "Workspace cannot be reset", func() {
			Example("cannot reset a vm workspace")
		})
		HTTP(func() {
			POST("/v1/workspaces/{name}/reset")
			Param("namespace")
			Response(StatusOK)
			Response("not_found", StatusNotFound)
			Response("invalid", StatusBadRequest)
		})
	})

	Method("clone", func() {
		Description("Clone an existing workspace under a new name, copying its spec and volume mounts")
		Payload(func() {
			Attribute("namespace", String, "Namespace", func() {
				Default("workspaces")
				Example("workspaces")
			})
			Attribute("name", String, "Source workspace name", func() {
				Example("my-workspace")
			})
			Attribute("new_name", String, "Name for the cloned workspace", func() {
				Pattern(`^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$`)
				MaxLength(63)
				Example("my-workspace-clone")
			})
			Attribute("image", String, "Override the container image on the clone", func() {
				Example("codercom/code-server:4.96.2")
			})
			Attribute("port", Int, "Override the container port on the clone", func() {
				Example(8080)
			})
			Attribute("cpu_request", String, "Override the CPU request on the clone", func() {
				Example("500m")
			})
			Attribute("memory_request", String, "Override the memory request on the clone", func() {
				Example("512Mi")
			})
			Attribute("cpu_limit", String, "Override the CPU limit on the clone", func() {
				Example("1")
			})
			Attribute("memory_limit", String, "Override the memory limit on the clone", func() {
				Example("2Gi")
			})
			Required("name", "new_name")
		})
		Result(WorkspaceResult)
		Error("not_found", String, "Source workspace not found", func() {
			Example("workspace \"my-workspace\" not found")
		})
		Error("already_exists", String, "A workspace with the new name already exists", func() {
			Example("workspace \"my-workspace-clone\" already exists")
		})
		Error("invalid", String, "Invalid clone specification", func() {
			Example("new_name must differ from name")
		})
		HTTP(func() {
			POST("/v1/workspaces/{name}/clone")
			Param("namespace")
			Response(StatusCreated)
			Response("not_found", StatusNotFound)
			Response("already_exists", StatusConflict)
			Response("invalid", StatusBadRequest)
		})
	})
})

var _ = Service("volumes", func() {
	Description("Volume (PVC) management service")

	Method("list", func() {
		Description("List all volumes")
		Payload(func() {
			Attribute("namespace", String, "Filter by namespace", func() {
				Default("workspaces")
				Example("workspaces")
			})
		})
		Result(ArrayOf(VolumeResult))
		HTTP(func() {
			GET("/v1/volumes")
			Param("namespace")
			Response(StatusOK)
		})
	})

	Method("get", func() {
		Description("Get a volume by name")
		Payload(func() {
			Attribute("namespace", String, "Namespace", func() {
				Default("workspaces")
				Example("workspaces")
			})
			Attribute("name", String, "Volume name", func() {
				Example("my-workspace-data")
			})
			Required("name")
		})
		Result(VolumeResult)
		Error("not_found", String, "Volume not found", func() {
			Example("volume \"my-workspace-data\" not found")
		})
		HTTP(func() {
			GET("/v1/volumes/{name}")
			Param("namespace")
			Response(StatusOK)
			Response("not_found", StatusNotFound)
		})
	})

	Method("create", func() {
		Description("Create a new volume (PVC)")
		Payload(CreateVolumePayload)
		Result(VolumeResult)
		Error("already_exists", String, "Volume already exists", func() {
			Example("volume \"my-workspace-data\" already exists")
		})
		Error("invalid", String, "Invalid volume specification", func() {
			Example("size must be a valid resource quantity")
		})
		HTTP(func() {
			POST("/v1/volumes")
			Response(StatusCreated)
			Response("already_exists", StatusConflict)
			Response("invalid", StatusBadRequest)
		})
	})

	Method("delete", func() {
		Description("Delete a volume")
		Payload(func() {
			Attribute("namespace", String, "Namespace", func() {
				Default("workspaces")
				Example("workspaces")
			})
			Attribute("name", String, "Volume name", func() {
				Example("my-workspace-data")
			})
			Required("name")
		})
		Error("not_found", String, "Volume not found", func() {
			Example("volume \"my-workspace-data\" not found")
		})
		HTTP(func() {
			DELETE("/v1/volumes/{name}")
			Param("namespace")
			Response(StatusNoContent)
			Response("not_found", StatusNotFound)
		})
	})
})

var _ = Service("sshkeys", func() {
	Description("SSH public key management service")

	Method("list", func() {
		Description("List the user's SSH public keys")
		Payload(func() {
			Attribute("namespace", String, "Filter by namespace", func() {
				Example("chris-at-fordham-id-au")
			})
		})
		Result(ArrayOf(SshKeyResult))
		HTTP(func() {
			GET("/v1/sshkeys")
			Param("namespace")
			Response(StatusOK)
		})
	})

	Method("get", func() {
		Description("Get an SSH public key by name")
		Payload(func() {
			Attribute("namespace", String, "Namespace", func() {
				Example("chris-at-fordham-id-au")
			})
			Attribute("name", String, "SSH key name", func() {
				Example("laptop-2025")
			})
			Required("name")
		})
		Result(SshKeyResult)
		Error("not_found", String, "SSH key not found", func() {
			Example("ssh key \"laptop-2025\" not found")
		})
		HTTP(func() {
			GET("/v1/sshkeys/{name}")
			Param("namespace")
			Response(StatusOK)
			Response("not_found", StatusNotFound)
		})
	})

	Method("create", func() {
		Description("Store a new SSH public key")
		Payload(CreateSshKeyPayload)
		Result(SshKeyResult)
		Error("already_exists", String, "SSH key already exists", func() {
			Example("ssh key \"laptop-2025\" already exists")
		})
		Error("invalid", String, "Invalid SSH key", func() {
			Example("public_key must be a valid SSH public key")
		})
		HTTP(func() {
			POST("/v1/sshkeys")
			Response(StatusCreated)
			Response("already_exists", StatusConflict)
			Response("invalid", StatusBadRequest)
		})
	})

	Method("delete", func() {
		Description("Delete an SSH public key")
		Payload(func() {
			Attribute("namespace", String, "Namespace", func() {
				Example("chris-at-fordham-id-au")
			})
			Attribute("name", String, "SSH key name", func() {
				Example("laptop-2025")
			})
			Required("name")
		})
		Error("not_found", String, "SSH key not found", func() {
			Example("ssh key \"laptop-2025\" not found")
		})
		HTTP(func() {
			DELETE("/v1/sshkeys/{name}")
			Param("namespace")
			Response(StatusNoContent)
			Response("not_found", StatusNotFound)
		})
	})
})

var _ = Service("images", func() {
	Description("Available workspace images")

	Method("list", func() {
		Description("List available workspace images")
		Result(ArrayOf(ImageResult))
		HTTP(func() {
			GET("/v1/images")
			Response(StatusOK)
		})
	})

	Method("create", func() {
		Description("Create a new image")
		Payload(CreateImagePayload)
		Result(ImageResult)
		Error("already_exists", String, "Image already exists", func() {
			Example("image \"code-server\" already exists")
		})
		Error("invalid", String, "Invalid image specification", func() {
			Example("default_port must be between 1 and 65535")
		})
		HTTP(func() {
			POST("/v1/images")
			Response(StatusCreated)
			Response("already_exists", StatusConflict)
			Response("invalid", StatusBadRequest)
		})
	})
})

var _ = Service("namespaces", func() {
	Description("Namespace management")

	Method("list", func() {
		Description("List available namespaces")
		Result(ArrayOf(NamespaceResult))
		HTTP(func() {
			GET("/v1/namespaces")
			Response(StatusOK)
		})
	})
})

var _ = Service("health", func() {
	Description("Health check service")

	Method("check", func() {
		Description("Health check endpoint")
		Result(func() {
			Attribute("status", String, "Health status", func() {
				Example("ok")
			})
			Required("status")
		})
		HTTP(func() {
			GET("/healthz")
			Response(StatusOK)
		})
	})
})
