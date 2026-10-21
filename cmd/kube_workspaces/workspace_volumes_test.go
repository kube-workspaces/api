package main

import (
	"encoding/json"
	"reflect"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestUpdateWorkspaceVolumeModes(t *testing.T) {
	for _, readOnly := range []bool{false, true} {
		oldMounts := []interface{}{
			map[string]interface{}{"name": "home", "mountPath": "/home/signal", "readOnly": !readOnly},
			map[string]interface{}{"name": "dshm", "mountPath": "/dev/shm"},
		}
		container := map[string]interface{}{"volumeMounts": oldMounts}
		init := map[string]interface{}{"name": "permfix", "volumeMounts": oldMounts}
		pod := map[string]interface{}{
			"containers": []interface{}{container}, "initContainers": []interface{}{init},
			"volumes": []interface{}{
				map[string]interface{}{"name": "home", "persistentVolumeClaim": map[string]interface{}{"claimName": "home"}},
				map[string]interface{}{"name": "dshm", "emptyDir": map[string]interface{}{"medium": "Memory"}},
			},
		}
		// Decode the PUT wire format, including explicit false.
		body, _ := json.Marshal([]workspaceVolumeMount{{Name: "home", MountPath: "/home/signal", Readonly: readOnly}})
		var mounts []workspaceVolumeMount
		if err := json.Unmarshal(body, &mounts); err != nil {
			t.Fatal(err)
		}
		updateWorkspaceVolumes(pod, container, mounts)
		if !reflect.DeepEqual(container["volumeMounts"], init["volumeMounts"]) {
			t.Fatal("permfix kept stale mounts")
		}
		got := container["volumeMounts"].([]interface{})
		if got[0].(map[string]interface{})["readOnly"] != readOnly || len(got) != 2 {
			t.Fatalf("mount mode or shm lost: %#v", got)
		}
		if len(pod["volumes"].([]interface{})) != 2 {
			t.Fatal("shm volume lost")
		}
		obj := &unstructured.Unstructured{Object: map[string]interface{}{"spec": map[string]interface{}{"template": map[string]interface{}{"spec": pod}}}}
		result := unstructuredToWorkspaceResult(obj)
		returned := result["volume_mounts"].([]workspaceVolumeMount)
		if len(returned) != 1 || returned[0].Readonly != readOnly {
			t.Fatalf("PUT response lost mode or exposed shm: %+v", returned)
		}
		updateWorkspaceVolumes(pod, container, nil)
		if len(container["volumeMounts"].([]interface{})) != 1 || len(init["volumeMounts"].([]interface{})) != 1 {
			t.Fatal("removing PVC left a stale init mount or removed shm")
		}
	}
}
