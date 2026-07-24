package k8s

import (
	"context"
	"encoding/json"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var imageGVR = schema.GroupVersionResource{
	Group:    "kubeworkspaces.io",
	Version:  "v1alpha1",
	Resource: "images",
}

// Image represents a parsed Image CR.
type Image struct {
	Name               string
	DisplayName        string
	Description        string
	Category           string
	Tags               []string
	Image              string
	DefaultPort        int32
	DefaultPath        string
	Icon               string
	DefaultArgs        []string
	DefaultEnv         []ImageEnvVar
	DefaultCredentials *ImageCredentials
	Privileged         bool
	HomepageURL        string
	SourceURL          string
	ImageHomepageURL   string
	DefaultUser        string
	DefaultHomedir     string
	DefaultShell       string
	Links              []ImageLink
	ProxyConfig        *ImageProxyConfig
	DefaultUID            *int64
	DefaultSharedMemory   bool
	DefaultInitContainers []ImageInitContainer
	AdditionalPorts       []ImagePort
}

// ImageCredentials represents default login credentials for a workspace image.
type ImageCredentials struct {
	Username string
	Password string
}

// ImageLink represents a named URL link for an image.
type ImageLink struct {
	Title string
	URL   string
}

// ImageEnvVar is an environment variable with optional placeholder support.
type ImageEnvVar struct {
	Name  string
	Value string
}

// ImageProxyConfig describes proxy behavior for an image.
type ImageProxyConfig struct {
	NeedsNoOpSW              bool
	WebSocketPaths           []string
	RewriteHostAbsolutePaths bool
	CustomRequestHeaders     map[string]string
	InjectBaseTag            bool
	TLSInsecure              bool
	PreservePathPrefix       bool
	AudioPort                int32
}

// ImagePort represents an additional container port to expose.
type ImagePort struct {
	Name     string
	Port     int32
	Protocol string
}

// ImageInitContainer represents a simplified init container spec for Image CR defaults.
type ImageInitContainer struct {
	Name    string
	Image   string
	Command []string
	Args    []string
	Env     []ImageEnvVar
	VolumeMounts []ImageVolumeMount
}

// ImageVolumeMount represents a volume mount for an init container.
type ImageVolumeMount struct {
	Name      string
	MountPath string
}

// ImageClient provides operations on Image custom resources.
type ImageClient struct {
	dynamic dynamic.Interface
}

// NewImageClient creates a new ImageClient.
func NewImageClient() (*ImageClient, error) {
	config, err := getConfig()
	if err != nil {
		return nil, err
	}

	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("unable to create dynamic client: %w", err)
	}

	return &ImageClient{dynamic: dynClient}, nil
}

// ListImages lists all Image CRs (cluster-scoped).
func (c *ImageClient) ListImages(ctx context.Context) ([]Image, error) {
	list, err := c.dynamic.Resource(imageGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	images := make([]Image, 0, len(list.Items))
	for i := range list.Items {
		img, err := parseImage(&list.Items[i])
		if err != nil {
			continue
		}
		images = append(images, *img)
	}
	return images, nil
}

// GetImage gets an Image CR by name.
func (c *ImageClient) GetImage(ctx context.Context, name string) (*Image, error) {
	obj, err := c.dynamic.Resource(imageGVR).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return parseImage(obj)
}

// GetImageRaw returns the raw unstructured Image CR object.
func (c *ImageClient) GetImageRaw(ctx context.Context, name string) (*unstructured.Unstructured, error) {
	return c.dynamic.Resource(imageGVR).Get(ctx, name, metav1.GetOptions{})
}

// GetImageByRef finds an Image CR whose spec.image matches the given reference.
func (c *ImageClient) GetImageByRef(ctx context.Context, imageRef string) (*Image, error) {
	images, err := c.ListImages(ctx)
	if err != nil {
		return nil, err
	}
	for _, img := range images {
		if img.Image == imageRef {
			return &img, nil
		}
	}
	return nil, fmt.Errorf("no Image CR found for image reference %q", imageRef)
}

// CreateImage creates a new Image CR.
func (c *ImageClient) CreateImage(ctx context.Context, name string, spec map[string]interface{}) (*unstructured.Unstructured, error) {
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "kubeworkspaces.io/v1alpha1",
			"kind":       "Image",
			"metadata": map[string]interface{}{
				"name": name,
			},
			"spec": spec,
		},
	}
	return c.dynamic.Resource(imageGVR).Create(ctx, obj, metav1.CreateOptions{})
}

// UpdateImage updates an existing Image CR.
func (c *ImageClient) UpdateImage(ctx context.Context, name string, spec map[string]interface{}) (*unstructured.Unstructured, error) {
	existing, err := c.GetImageRaw(ctx, name)
	if err != nil {
		return nil, err
	}
	existing.Object["spec"] = spec
	return c.dynamic.Resource(imageGVR).Update(ctx, existing, metav1.UpdateOptions{})
}

// DeleteImage deletes an Image CR.
func (c *ImageClient) DeleteImage(ctx context.Context, name string) error {
	return c.dynamic.Resource(imageGVR).Delete(ctx, name, metav1.DeleteOptions{})
}

func parseImage(obj *unstructured.Unstructured) (*Image, error) {
	spec, ok := obj.Object["spec"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("missing spec in Image %s", obj.GetName())
	}

	img := &Image{
		Name:        obj.GetName(),
		DisplayName: strField(spec, "displayName"),
		Description: strField(spec, "description"),
		Category:    strField(spec, "category"),
		Image:       strField(spec, "image"),
		DefaultPath: strField(spec, "defaultPath"),
		Icon:        strField(spec, "icon"),
	}

	// Parse tags
	if tags, ok := spec["tags"].([]interface{}); ok {
		for _, t := range tags {
			if s, ok := t.(string); ok {
				img.Tags = append(img.Tags, s)
			}
		}
	}

	if v, ok := spec["defaultPort"].(float64); ok {
		img.DefaultPort = int32(v)
	} else if v, ok := spec["defaultPort"].(int64); ok {
		img.DefaultPort = int32(v)
	} else if v, ok := spec["defaultPort"].(int); ok {
		img.DefaultPort = int32(v)
	} else if v, ok := spec["defaultPort"].(json.Number); ok {
		n, _ := v.Int64()
		img.DefaultPort = int32(n)
	}

	if args, ok := spec["defaultArgs"].([]interface{}); ok {
		for _, a := range args {
			if s, ok := a.(string); ok {
				img.DefaultArgs = append(img.DefaultArgs, s)
			}
		}
	}

	if envs, ok := spec["defaultEnv"].([]interface{}); ok {
		for _, e := range envs {
			if m, ok := e.(map[string]interface{}); ok {
				img.DefaultEnv = append(img.DefaultEnv, ImageEnvVar{
					Name:  strField(m, "name"),
					Value: strField(m, "value"),
				})
			}
		}
	}

	img.Privileged = boolField(spec, "privileged")
	img.HomepageURL = strField(spec, "homepageURL")
	img.SourceURL = strField(spec, "sourceURL")
	img.ImageHomepageURL = strField(spec, "imageHomepageURL")
	img.DefaultUser = strField(spec, "defaultUser")
	img.DefaultHomedir = strField(spec, "defaultHomedir")
	img.DefaultShell = strField(spec, "defaultShell")

	if links, ok := spec["links"].([]interface{}); ok {
		for _, l := range links {
			if m, ok := l.(map[string]interface{}); ok {
				img.Links = append(img.Links, ImageLink{
					Title: strField(m, "title"),
					URL:   strField(m, "url"),
				})
			}
		}
	}

	if dc, ok := spec["defaultCredentials"].(map[string]interface{}); ok {
		img.DefaultCredentials = &ImageCredentials{
			Username: strField(dc, "username"),
			Password: strField(dc, "password"),
		}
	}

	if pc, ok := spec["proxyConfig"].(map[string]interface{}); ok {
		img.ProxyConfig = &ImageProxyConfig{
			NeedsNoOpSW:              boolField(pc, "needsNoopSW"),
			RewriteHostAbsolutePaths: boolField(pc, "rewriteHostAbsolutePaths"),
			InjectBaseTag:            boolField(pc, "injectBaseTag"),
			TLSInsecure:              boolField(pc, "tlsInsecure"),
			PreservePathPrefix:       boolField(pc, "preservePathPrefix"),
			AudioPort:                int32Field(pc, "audioPort"),
		}
		if paths, ok := pc["websocketPaths"].([]interface{}); ok {
			for _, p := range paths {
				if s, ok := p.(string); ok {
					img.ProxyConfig.WebSocketPaths = append(img.ProxyConfig.WebSocketPaths, s)
				}
			}
		}
		if headers, ok := pc["customRequestHeaders"].(map[string]interface{}); ok {
			img.ProxyConfig.CustomRequestHeaders = make(map[string]string, len(headers))
			for k, v := range headers {
				if s, ok := v.(string); ok {
					img.ProxyConfig.CustomRequestHeaders[k] = s
				}
			}
		}
	}

	// Parse defaultUID
	if v, ok := spec["defaultUID"].(float64); ok {
		uid := int64(v)
		img.DefaultUID = &uid
	} else if v, ok := spec["defaultUID"].(int64); ok {
		img.DefaultUID = &v
	} else if v, ok := spec["defaultUID"].(json.Number); ok {
		n, _ := v.Int64()
		img.DefaultUID = &n
	}

	// Parse defaultSharedMemory
	if v, ok := spec["defaultSharedMemory"].(bool); ok {
		img.DefaultSharedMemory = v
	}

	// Parse defaultInitContainers
	if initContainers, ok := spec["defaultInitContainers"].([]interface{}); ok {
		for _, ic := range initContainers {
			if m, ok := ic.(map[string]interface{}); ok {
				initC := ImageInitContainer{
					Name:  strField(m, "name"),
					Image: strField(m, "image"),
				}
				if cmd, ok := m["command"].([]interface{}); ok {
					for _, c := range cmd {
						if s, ok := c.(string); ok {
							initC.Command = append(initC.Command, s)
						}
					}
				}
				if args, ok := m["args"].([]interface{}); ok {
					for _, a := range args {
						if s, ok := a.(string); ok {
							initC.Args = append(initC.Args, s)
						}
					}
				}
				if envs, ok := m["env"].([]interface{}); ok {
					for _, e := range envs {
						if em, ok := e.(map[string]interface{}); ok {
							initC.Env = append(initC.Env, ImageEnvVar{
								Name:  strField(em, "name"),
								Value: strField(em, "value"),
							})
						}
					}
				}
				if vms, ok := m["volumeMounts"].([]interface{}); ok {
					for _, vm := range vms {
						if vmm, ok := vm.(map[string]interface{}); ok {
							initC.VolumeMounts = append(initC.VolumeMounts, ImageVolumeMount{
								Name:      strField(vmm, "name"),
								MountPath: strField(vmm, "mountPath"),
							})
						}
					}
				}
				img.DefaultInitContainers = append(img.DefaultInitContainers, initC)
			}
		}
	}

	// Parse additionalPorts
	if ports, ok := spec["additionalPorts"].([]interface{}); ok {
		for _, p := range ports {
			if m, ok := p.(map[string]interface{}); ok {
				img.AdditionalPorts = append(img.AdditionalPorts, ImagePort{
					Name:     strField(m, "name"),
					Port:     int32Field(m, "port"),
					Protocol: strField(m, "protocol"),
				})
			}
		}
	}

	return img, nil
}

func strField(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func boolField(m map[string]interface{}, key string) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}

func int32Field(m map[string]interface{}, key string) int32 {
	if v, ok := m[key].(float64); ok {
		return int32(v)
	}
	if v, ok := m[key].(int64); ok {
		return int32(v)
	}
	if v, ok := m[key].(json.Number); ok {
		n, _ := v.Int64()
		return int32(n)
	}
	return 0
}
