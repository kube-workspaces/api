package kubeworkspaces

import (
	"fmt"
	"regexp"

	"github.com/kube-workspaces/api/gen/workspaces"
	"github.com/kube-workspaces/api/internal/k8s"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/validation"
)

var containerInitAccountName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

func defaultContainerInitSnapshot(img *k8s.Image) map[string]interface{} {
	if img.DefaultContainerInit == nil {
		return nil
	}
	config := map[string]interface{}{"mode": img.DefaultContainerInit.Mode}
	if img.DefaultContainerInit.Mode == "disabled" {
		return config
	}
	if img.DefaultContainerInit.DefaultUser != "" {
		config["defaultUser"] = img.DefaultContainerInit.DefaultUser
	}
	if img.DefaultContainerInit.RunAsUser != "" {
		config["runAsUser"] = img.DefaultContainerInit.RunAsUser
	}
	if img.DefaultContainerInit.Mode != "disabled" && img.DefaultUserData != "" {
		config["userData"] = img.DefaultUserData
	}
	return config
}

func resolveContainerInitOverride(defaults map[string]interface{}, override *workspaces.WorkspaceContainerInit) map[string]interface{} {
	if override == nil {
		return defaults
	}
	config := map[string]interface{}{"mode": override.Mode}
	if override.Mode == "disabled" {
		return config
	}
	if defaults != nil {
		for _, key := range []string{"defaultUser", "runAsUser"} {
			if value, ok := defaults[key]; ok {
				config[key] = value
			}
		}
		if data, ok := defaults["userData"]; ok {
			config["userData"] = data
		}
	}
	for key, value := range map[string]*string{"defaultUser": override.DefaultUser, "runAsUser": override.RunAsUser} {
		if value != nil {
			delete(config, key)
			if *value != "" {
				config[key] = *value
			}
		}
	}
	if override.UserDataSecret != nil {
		delete(config, "userData")
		config["userDataSecretRef"] = map[string]interface{}{"name": *override.UserDataSecret}
	}
	if override.UserData != nil {
		// Preserve explicit empty input so validation rejects it instead of
		// silently falling back to an inherited document.
		config["userData"] = *override.UserData
	}
	return config
}

func validateContainerInitWorkspace(ws *unstructured.Unstructured) error {
	cfg, found, err := unstructured.NestedMap(ws.Object, "spec", "containerInit")
	if err != nil {
		return fmt.Errorf("invalid container initialization configuration")
	}
	if !found {
		return nil
	}
	typeName, _, _ := unstructured.NestedString(ws.Object, "spec", "type")
	if typeName == "vm" {
		return fmt.Errorf("container_init is only supported for container and scratch workspaces")
	}
	mode, _ := cfg["mode"].(string)
	if mode == "disabled" {
		return nil
	}
	if mode != "injected" && mode != "baked-in" {
		return fmt.Errorf("container_init mode must be disabled, injected or baked-in")
	}
	for _, key := range []string{"defaultUser", "runAsUser"} {
		if value, ok := cfg[key]; ok {
			name, ok := value.(string)
			if !ok || !containerInitAccountName.MatchString(name) {
				return fmt.Errorf("container_init identity must be a valid account name")
			}
			if mode != "injected" {
				return fmt.Errorf("container_init identity options require injected mode")
			}
		}
	}
	if runAs, _ := cfg["runAsUser"].(string); runAs != "" && (mode != "injected" || runAs == "root") {
		return fmt.Errorf("container_init run_as_user requires injected mode and a non-root account")
	}
	data, hasData := cfg["userData"].(string)
	ref, hasRef := cfg["userDataSecretRef"].(map[string]interface{})
	if hasData == hasRef {
		return fmt.Errorf("container_init requires either user_data or user_data_secret")
	}
	if hasData && (len(data) == 0 || len(data) > 262144) {
		return fmt.Errorf("container_init user_data must contain 1 to 262144 bytes")
	}
	if hasRef {
		name, _ := ref["name"].(string)
		if name == "" || len(validation.IsDNS1123Subdomain(name)) > 0 {
			return fmt.Errorf("container_init user_data_secret must be a valid same-namespace Secret name")
		}
	}
	if mode == "injected" {
		containers, _, _ := unstructured.NestedSlice(ws.Object, "spec", "template", "spec", "containers")
		if len(containers) == 0 {
			return fmt.Errorf("injected initialization requires a main container")
		}
		main, _ := containers[0].(map[string]interface{})
		command, _, _ := unstructured.NestedStringSlice(main, "command")
		if len(command) == 0 || command[0] == "" {
			return fmt.Errorf("injected initialization requires defaultCommand or an explicit container command")
		}
	}
	return nil
}
