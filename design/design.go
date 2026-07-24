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
	})
	Attribute("value", String, "Toleration value", func() {
		Example("true")
	})
	Attribute("effect", String, "Taint effect: NoSchedule, PreferNoSchedule, or NoExecute", func() {
		Enum("NoSchedule", "PreferNoSchedule", "NoExecute", "")
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
	Attribute("container", WorkspaceContainer, "Main container spec")
	Attribute("volume_mounts", ArrayOf(VolumeMount), "Volumes to mount")
	Attribute("env", ArrayOf(EnvVar), "Custom environment variables to inject into the workspace container")
	Attribute("tolerations", ArrayOf(Toleration), "Pod tolerations for scheduling")
	Attribute("node_selector", MapOf(String, String), "Node selector labels for scheduling")
	Attribute("shared_memory", Boolean, "Mount /dev/shm as an emptyDir with medium=Memory (required for Chrome, ML frameworks)", func() {
		Default(false)
	})
	Attribute("image_pull_policy", String, "Image pull policy for the workspace container (Always, IfNotPresent, Never)", func() {
		Enum("Always", "IfNotPresent", "Never")
		Default("IfNotPresent")
	})
	Required("name", "container")
})

var WorkspaceCondition = Type("WorkspaceCondition", func() {
	Description("Condition of a workspace")
	Attribute("type", String, "Condition type")
	Attribute("status", String, "Condition status")
	Attribute("reason", String, "Brief reason")
	Attribute("message", String, "Detailed message")
	Attribute("last_transition_time", String, "Last transition time")
})

var ContainerState = Type("ContainerState", func() {
	Description("State of the workspace container")
	Attribute("state", String, "Current state: running, waiting, terminated", func() {
		Enum("running", "waiting", "terminated", "unknown")
	})
	Attribute("reason", String, "Reason for the state")
	Attribute("message", String, "Details about the state")
	Attribute("started_at", String, "Time the container started")
})

var WorkspaceResult = ResultType("application/vnd.workspace+json", func() {
	Description("A workspace resource")
	Attributes(func() {
		Attribute("name", String, "Workspace name")
		Attribute("namespace", String, "Kubernetes namespace")
		Attribute("image", String, "Container image")
		Attribute("port", Int, "Container port")
		Attribute("cpu_request", String, "CPU request")
		Attribute("memory_request", String, "Memory request")
		Attribute("cpu_limit", String, "CPU limit")
		Attribute("memory_limit", String, "Memory limit")
		Attribute("ready_replicas", Int, "Number of ready replicas")
		Attribute("container_state", ContainerState, "Container state")
		Attribute("conditions", ArrayOf(WorkspaceCondition), "Workspace conditions")
		Attribute("stopped", Boolean, "Whether the workspace is stopped")
		Attribute("created_at", String, "Creation timestamp")
		Attribute("volume_mounts", ArrayOf(VolumeMount), "Attached volumes")
	})
	Required("name", "namespace", "image", "ready_replicas", "stopped")
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
	})
	Required("name", "size")
})

var VolumeResult = ResultType("application/vnd.volume+json", func() {
	Description("A persistent volume claim")
	Attributes(func() {
		Attribute("name", String, "PVC name")
		Attribute("namespace", String, "Kubernetes namespace")
		Attribute("size", String, "Storage size")
		Attribute("storage_class", String, "Storage class")
		Attribute("access_mode", String, "Access mode")
		Attribute("phase", String, "PVC phase (Bound, Pending, etc.)")
		Attribute("created_at", String, "Creation timestamp")
		Attribute("labels", MapOf(String, String), "Kubernetes labels on the PVC")
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
	Attribute("description", String, "Description of the image")
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
	Attribute("icon", String, "Icon identifier")
	Attribute("default_args", ArrayOf(String), "Default command-line args")
	Attribute("default_env", ArrayOf(ImageEnvVar), "Default environment variables")
	Attribute("privileged", Boolean, "Run container in privileged mode", func() {
		Default(false)
	})
	Attribute("homepage_url", String, "Project homepage or documentation URL")
	Attribute("source_url", String, "Source code repository URL")
	Attribute("image_homepage_url", String, "Container image registry page (e.g. Docker Hub)")
	Attribute("default_user", String, "Default user for this image")
	Attribute("default_homedir", String, "Default home directory for the default user")
	Attribute("default_shell", String, "Default shell for exec/console sessions (e.g. /bin/bash)")
	Attribute("links", ArrayOf(ImageLink), "Additional relevant URLs for this image")
	Attribute("default_credentials", ImageCredentials, "Default login credentials for this image")
	Attribute("proxy_config", ImageProxyConfig, "Proxy behavior configuration")
	Attribute("default_uid", Int64, "UID that the main container runs as (sets runAsUser and fsGroup)")
	Attribute("default_shared_memory", Boolean, "Automatically mount /dev/shm as emptyDir with medium=Memory (required for Selkies streaming, Chrome, ML frameworks)")
	Required("name", "image", "default_port")
})

var ImageEnvVar = Type("ImageEnvVar", func() {
	Description("Environment variable with optional placeholder support")
	Attribute("name", String, "Name of the environment variable")
	Attribute("value", String, "Value (supports {{namespace}} and {{name}} placeholders)")
	Required("name", "value")
})

var ImageLink = Type("ImageLink", func() {
	Description("A named URL link for an image")
	Attribute("title", String, "Display label for the link")
	Attribute("url", String, "Link target URL")
	Required("title", "url")
})

var ImageCredentials = Type("ImageCredentials", func() {
	Description("Default login credentials for a workspace image")
	Attribute("username", String, "Default username")
	Attribute("password", String, "Default password")
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
	Attribute("custom_request_headers", MapOf(String, String), "Additional headers to inject into proxied requests")
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
		Attribute("cr_name", String, "Kubernetes resource name (metadata.name)")
		Attribute("name", String, "Display name")
		Attribute("image", String, "Full image reference")
		Attribute("description", String, "Description of the image")
		Attribute("category", String, "Category for grouping (e.g. Desktop, IDE, Tool, Game)")
		Attribute("tags", ArrayOf(String), "Tags for filtering/searching images")
		Attribute("default_port", Int, "Default container port")
		Attribute("default_path", String, "Default URL path for connecting (e.g. /vnc.html?resize=remote)")
		Attribute("proxy_config", ImageProxyConfig, "Proxy behavior configuration for this image")
		Attribute("icon", String, "Icon identifier")
		Attribute("default_args", ArrayOf(String), "Default command-line args injected at workspace creation")
		Attribute("default_env", ArrayOf(ImageEnvVar), "Default environment variables injected at workspace creation")
		Attribute("default_uid", Int64, "UID that the main container runs as (sets runAsUser and fsGroup)")
		Attribute("default_shared_memory", Boolean, "Automatically mount /dev/shm as emptyDir with medium=Memory (required for Selkies streaming, Chrome, ML frameworks)")
		Attribute("privileged", Boolean, "Run container in privileged mode")
		Attribute("homepage_url", String, "Project homepage or documentation URL")
		Attribute("source_url", String, "Source code repository URL")
		Attribute("image_homepage_url", String, "Container image registry page (e.g. Docker Hub)")
		Attribute("default_user", String, "Default user for this image")
		Attribute("default_homedir", String, "Default home directory for the default user")
		Attribute("default_shell", String, "Default shell for exec/console sessions (e.g. /bin/bash)")
		Attribute("links", ArrayOf(ImageLink), "Additional relevant URLs for this image")
		Attribute("default_credentials", ImageCredentials, "Default login credentials for this image")
	})
	Required("cr_name", "name", "image", "default_port")
})

// Namespace types

var NamespaceResult = ResultType("application/vnd.namespace+json", func() {
	Description("A Kubernetes namespace")
	Attributes(func() {
		Attribute("name", String, "Namespace name")
		Attribute("phase", String, "Namespace phase")
		Attribute("created_at", String, "Creation timestamp")
	})
	Required("name", "phase")
})

// Service definitions

var _ = Service("workspaces", func() {
	Description("Workspace management service")

	Method("list", func() {
		Description("List all workspaces")
		Payload(func() {
			Attribute("namespace", String, "Filter by namespace", func() {
				Default("workspaces")
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
			})
			Attribute("name", String, "Workspace name")
			Required("name")
		})
		Result(WorkspaceResult)
		Error("not_found", String, "Workspace not found")
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
		Error("already_exists", String, "Workspace already exists")
		Error("invalid", String, "Invalid workspace specification")
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
			})
			Attribute("name", String, "Workspace name")
			Required("name")
		})
		Error("not_found", String, "Workspace not found")
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
			})
			Attribute("name", String, "Workspace name")
			Required("name")
		})
		Result(WorkspaceResult)
		Error("not_found", String, "Workspace not found")
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
			})
			Attribute("name", String, "Workspace name")
			Required("name")
		})
		Result(WorkspaceResult)
		Error("not_found", String, "Workspace not found")
		HTTP(func() {
			POST("/v1/workspaces/{name}/stop")
			Param("namespace")
			Response(StatusOK)
			Response("not_found", StatusNotFound)
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
			})
			Attribute("name", String, "Volume name")
			Required("name")
		})
		Result(VolumeResult)
		Error("not_found", String, "Volume not found")
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
		Error("already_exists", String, "Volume already exists")
		Error("invalid", String, "Invalid volume specification")
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
			})
			Attribute("name", String, "Volume name")
			Required("name")
		})
		Error("not_found", String, "Volume not found")
		HTTP(func() {
			DELETE("/v1/volumes/{name}")
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
		Error("already_exists", String, "Image already exists")
		Error("invalid", String, "Invalid image specification")
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
			Attribute("status", String, "Health status")
			Required("status")
		})
		HTTP(func() {
			GET("/healthz")
			Response(StatusOK)
		})
	})
})
