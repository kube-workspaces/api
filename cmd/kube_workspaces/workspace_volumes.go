package main

import "reflect"

type workspaceVolumeMount struct {
	Name      string `json:"name"`
	MountPath string `json:"mount_path"`
	Readonly  bool   `json:"readonly"`
}

// updateWorkspaceVolumes replaces the editable PVC mounts, retaining auxiliary
// volumes such as /dev/shm. Init containers that inherited the main mounts at
// creation must follow edits too, including changes to the read-only flag.
func updateWorkspaceVolumes(podSpec, container map[string]interface{}, mounts []workspaceVolumeMount) {
	oldMounts, _ := container["volumeMounts"].([]interface{})
	oldVolumes, _ := podSpec["volumes"].([]interface{})
	pvcNames := map[string]bool{}
	mainNames := map[string]bool{}
	for _, entry := range oldMounts {
		mainNames[entry.(map[string]interface{})["name"].(string)] = true
	}
	volumes := make([]interface{}, 0, len(oldVolumes)+len(mounts))
	for _, entry := range oldVolumes {
		volume := entry.(map[string]interface{})
		if _, pvc := volume["persistentVolumeClaim"]; pvc && mainNames[volume["name"].(string)] {
			pvcNames[volume["name"].(string)] = true
		} else {
			volumes = append(volumes, entry)
		}
	}
	newMounts := make([]interface{}, 0, len(mounts)+len(oldMounts))
	for _, mount := range mounts {
		newMounts = append(newMounts, map[string]interface{}{
			"name": mount.Name, "mountPath": mount.MountPath, "readOnly": mount.Readonly,
		})
		volumes = append(volumes, map[string]interface{}{
			"name": mount.Name, "persistentVolumeClaim": map[string]interface{}{"claimName": mount.Name},
		})
	}
	for _, entry := range oldMounts {
		mount := entry.(map[string]interface{})
		if !pvcNames[mount["name"].(string)] {
			newMounts = append(newMounts, entry)
		}
	}
	initContainers, _ := podSpec["initContainers"].([]interface{})
	for _, entry := range initContainers {
		init := entry.(map[string]interface{})
		if reflect.DeepEqual(init["volumeMounts"], oldMounts) {
			init["volumeMounts"] = newMounts
		}
	}
	container["volumeMounts"] = newMounts
	podSpec["volumes"] = volumes
}
