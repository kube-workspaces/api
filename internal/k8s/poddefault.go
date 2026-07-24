package k8s

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var podDefaultGVR = schema.GroupVersionResource{
	Group:    "kubeworkspaces.io",
	Version:  "v1alpha1",
	Resource: "poddefaults",
}

// PodDefault represents a parsed PodDefault CR.
type PodDefault struct {
	Name               string
	Namespace          string
	Desc               string
	Selector           *metav1.LabelSelector
	Env                []PodDefaultEnvVar
	VolumeMounts       []PodDefaultVolumeMount
	Volumes            []map[string]interface{}
	ServiceAccountName string
	Annotations        map[string]string
	Labels             map[string]string
}

// PodDefaultEnvVar is an environment variable to inject.
type PodDefaultEnvVar struct {
	Name  string
	Value string
}

// PodDefaultVolumeMount is a volume mount to inject.
type PodDefaultVolumeMount struct {
	Name      string
	MountPath string
	ReadOnly  bool
}

// PodDefaultClient provides operations on PodDefault custom resources.
type PodDefaultClient struct {
	dynamic dynamic.Interface
}

// NewPodDefaultClient creates a new PodDefaultClient.
func NewPodDefaultClient() (*PodDefaultClient, error) {
	config, err := getConfig()
	if err != nil {
		return nil, err
	}

	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("unable to create dynamic client: %w", err)
	}

	return &PodDefaultClient{dynamic: dynClient}, nil
}

// ListPodDefaults lists all PodDefault CRs in a namespace.
func (c *PodDefaultClient) ListPodDefaults(ctx context.Context, namespace string) ([]PodDefault, error) {
	list, err := c.dynamic.Resource(podDefaultGVR).Namespace(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	results := make([]PodDefault, 0, len(list.Items))
	for i := range list.Items {
		pd, err := parsePodDefault(&list.Items[i])
		if err != nil {
			continue
		}
		results = append(results, *pd)
	}
	return results, nil
}

// GetMatchingPodDefaults returns PodDefaults in the given namespace whose selector
// matches the provided workspace labels. PodDefaults with no selector match all workspaces.
func (c *PodDefaultClient) GetMatchingPodDefaults(ctx context.Context, namespace string, workspaceLabels map[string]string) ([]PodDefault, error) {
	allDefaults, err := c.ListPodDefaults(ctx, namespace)
	if err != nil {
		return nil, err
	}

	var matching []PodDefault
	for _, pd := range allDefaults {
		if pd.Selector == nil {
			// No selector means it applies to all workspaces in the namespace
			matching = append(matching, pd)
			continue
		}
		selector, err := metav1.LabelSelectorAsSelector(pd.Selector)
		if err != nil {
			continue // skip invalid selectors
		}
		if selector.Matches(labels.Set(workspaceLabels)) {
			matching = append(matching, pd)
		}
	}
	return matching, nil
}

func parsePodDefault(obj *unstructured.Unstructured) (*PodDefault, error) {
	spec, ok := obj.Object["spec"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("missing spec in PodDefault %s", obj.GetName())
	}

	pd := &PodDefault{
		Name:      obj.GetName(),
		Namespace: obj.GetNamespace(),
		Desc:      strField(spec, "desc"),
	}

	// Parse selector
	if sel, ok := spec["selector"].(map[string]interface{}); ok {
		pd.Selector = &metav1.LabelSelector{}
		if ml, ok := sel["matchLabels"].(map[string]interface{}); ok {
			pd.Selector.MatchLabels = make(map[string]string, len(ml))
			for k, v := range ml {
				if s, ok := v.(string); ok {
					pd.Selector.MatchLabels[k] = s
				}
			}
		}
	}

	// Parse env
	if envs, ok := spec["env"].([]interface{}); ok {
		for _, e := range envs {
			if m, ok := e.(map[string]interface{}); ok {
				pd.Env = append(pd.Env, PodDefaultEnvVar{
					Name:  strField(m, "name"),
					Value: strField(m, "value"),
				})
			}
		}
	}

	// Parse volumeMounts
	if vms, ok := spec["volumeMounts"].([]interface{}); ok {
		for _, vm := range vms {
			if m, ok := vm.(map[string]interface{}); ok {
				pd.VolumeMounts = append(pd.VolumeMounts, PodDefaultVolumeMount{
					Name:      strField(m, "name"),
					MountPath: strField(m, "mountPath"),
					ReadOnly:  boolField(m, "readOnly"),
				})
			}
		}
	}

	// Parse volumes (keep as raw maps for pass-through)
	if vols, ok := spec["volumes"].([]interface{}); ok {
		for _, v := range vols {
			if m, ok := v.(map[string]interface{}); ok {
				pd.Volumes = append(pd.Volumes, m)
			}
		}
	}

	pd.ServiceAccountName = strField(spec, "serviceAccountName")

	// Parse annotations
	if ann, ok := spec["annotations"].(map[string]interface{}); ok {
		pd.Annotations = make(map[string]string, len(ann))
		for k, v := range ann {
			if s, ok := v.(string); ok {
				pd.Annotations[k] = s
			}
		}
	}

	// Parse labels
	if lbl, ok := spec["labels"].(map[string]interface{}); ok {
		pd.Labels = make(map[string]string, len(lbl))
		for k, v := range lbl {
			if s, ok := v.(string); ok {
				pd.Labels[k] = s
			}
		}
	}

	return pd, nil
}
