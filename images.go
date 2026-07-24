package kubeworkspaces

import (
	"context"
	"fmt"
	"strings"

	images "github.com/kube-workspaces/api/gen/images"
	"github.com/kube-workspaces/api/internal/k8s"
	"goa.design/clue/log"
)

// images service implementation.
type imagessrvc struct {
	imageClient *k8s.ImageClient
}

// NewImages returns the images service implementation.
func NewImages(imageClient *k8s.ImageClient) images.Service {
	return &imagessrvc{imageClient: imageClient}
}

// List available workspace images
func (s *imagessrvc) List(ctx context.Context) (res []*images.Image, err error) {
	log.Printf(ctx, "images.list")

	crImages, err := s.imageClient.ListImages(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list images: %w", err)
	}

	res = make([]*images.Image, 0, len(crImages))
	for _, img := range crImages {
		res = append(res, imageToResult(&img))
	}
	return res, nil
}

// Create a new image
func (s *imagessrvc) Create(ctx context.Context, p *images.CreateImagePayload) (res *images.Image, err error) {
	log.Printf(ctx, "images.create name=%s", p.Name)

	// Derive the CR name from the display name (lowercase, spaces to hyphens)
	crName := strings.ToLower(strings.ReplaceAll(p.Name, " ", "-"))

	// Check if already exists
	if _, getErr := s.imageClient.GetImage(ctx, crName); getErr == nil {
		return nil, images.AlreadyExists(fmt.Sprintf("image %q already exists", crName))
	}

	// Build the spec
	spec := map[string]interface{}{
		"image":       p.Image,
		"displayName": p.Name,
		"defaultPort": int64(p.DefaultPort),
	}

	if p.Description != nil {
		spec["description"] = *p.Description
	}
	if p.Category != nil {
		spec["category"] = *p.Category
	}
	if len(p.Tags) > 0 {
		tags := make([]interface{}, len(p.Tags))
		for i, t := range p.Tags {
			tags[i] = t
		}
		spec["tags"] = tags
	}
	if p.DefaultPath != nil {
		spec["defaultPath"] = *p.DefaultPath
	}
	if p.Icon != nil {
		spec["icon"] = *p.Icon
	}
	if p.Privileged {
		spec["privileged"] = true
	}
	if p.HomepageURL != nil {
		spec["homepageURL"] = *p.HomepageURL
	}
	if p.SourceURL != nil {
		spec["sourceURL"] = *p.SourceURL
	}
	if p.ImageHomepageURL != nil {
		spec["imageHomepageURL"] = *p.ImageHomepageURL
	}
	if p.DefaultUser != nil {
		spec["defaultUser"] = *p.DefaultUser
	}
	if p.DefaultHomedir != nil {
		spec["defaultHomedir"] = *p.DefaultHomedir
	}
	if p.DefaultShell != nil {
		spec["defaultShell"] = *p.DefaultShell
	}
	if len(p.Links) > 0 {
		links := make([]interface{}, len(p.Links))
		for i, l := range p.Links {
			links[i] = map[string]interface{}{
				"title": l.Title,
				"url":   l.URL,
			}
		}
		spec["links"] = links
	}
	if p.DefaultCredentials != nil {
		dc := map[string]interface{}{}
		if p.DefaultCredentials.Username != nil {
			dc["username"] = *p.DefaultCredentials.Username
		}
		if p.DefaultCredentials.Password != nil {
			dc["password"] = *p.DefaultCredentials.Password
		}
		spec["defaultCredentials"] = dc
	}
	if len(p.DefaultArgs) > 0 {
		args := make([]interface{}, len(p.DefaultArgs))
		for i, a := range p.DefaultArgs {
			args[i] = a
		}
		spec["defaultArgs"] = args
	}
	if len(p.DefaultEnv) > 0 {
		envs := make([]interface{}, 0, len(p.DefaultEnv))
		for _, e := range p.DefaultEnv {
			envs = append(envs, map[string]interface{}{
				"name":  e.Name,
				"value": e.Value,
			})
		}
		spec["defaultEnv"] = envs
	}
	if p.ProxyConfig != nil {
		pc := map[string]interface{}{
			"needsNoopSW":              p.ProxyConfig.NeedsNoopSw,
			"rewriteHostAbsolutePaths": p.ProxyConfig.RewriteHostAbsolutePaths,
			"injectBaseTag":            p.ProxyConfig.InjectBaseTag,
		}
		if p.ProxyConfig.TLSInsecure {
			pc["tlsInsecure"] = true
		}
		if p.ProxyConfig.PreservePathPrefix {
			pc["preservePathPrefix"] = true
		}
		if len(p.ProxyConfig.WebsocketPaths) > 0 {
			paths := make([]interface{}, len(p.ProxyConfig.WebsocketPaths))
			for i, wp := range p.ProxyConfig.WebsocketPaths {
				paths[i] = wp
			}
			pc["websocketPaths"] = paths
		}
		if len(p.ProxyConfig.CustomRequestHeaders) > 0 {
			headers := make(map[string]interface{}, len(p.ProxyConfig.CustomRequestHeaders))
			for k, v := range p.ProxyConfig.CustomRequestHeaders {
				headers[k] = v
			}
			pc["customRequestHeaders"] = headers
		}
		spec["proxyConfig"] = pc
	}
	if p.DefaultUID != nil {
		spec["defaultUID"] = *p.DefaultUID
	}
	if p.DefaultSharedMemory != nil && *p.DefaultSharedMemory {
		spec["defaultSharedMemory"] = true
	}

	_, err = s.imageClient.CreateImage(ctx, crName, spec)
	if err != nil {
		return nil, fmt.Errorf("failed to create image: %w", err)
	}

	// Return the created image
	img, err := s.imageClient.GetImage(ctx, crName)
	if err != nil {
		return nil, fmt.Errorf("failed to get created image: %w", err)
	}

	return imageToResult(img), nil
}

// imageToResult converts an internal Image to the API result type.
func imageToResult(img *k8s.Image) *images.Image {
	result := &images.Image{
		CrName:           img.Name,
		Name:             img.DisplayName,
		Image:            img.Image,
		Description:      strPtr(img.Description),
		Category:         strPtr(img.Category),
		DefaultPort:      int(img.DefaultPort),
		DefaultPath:      strPtr(img.DefaultPath),
		Icon:             strPtr(img.Icon),
		Privileged:       boolPtr(img.Privileged),
		HomepageURL:      strPtr(img.HomepageURL),
		SourceURL:        strPtr(img.SourceURL),
		ImageHomepageURL: strPtr(img.ImageHomepageURL),
		DefaultUser:      strPtr(img.DefaultUser),
		DefaultHomedir:   strPtr(img.DefaultHomedir),
		DefaultShell:     strPtr(img.DefaultShell),
		DefaultUID:       img.DefaultUID,
	}
	if img.DefaultSharedMemory {
		result.DefaultSharedMemory = boolPtr(true)
	}
	if len(img.Tags) > 0 {
		result.Tags = img.Tags
	}
	if len(img.DefaultArgs) > 0 {
		result.DefaultArgs = img.DefaultArgs
	}
	if len(img.DefaultEnv) > 0 {
		result.DefaultEnv = make([]*images.ImageEnvVar, len(img.DefaultEnv))
		for i, e := range img.DefaultEnv {
			result.DefaultEnv[i] = &images.ImageEnvVar{Name: e.Name, Value: e.Value}
		}
	}
	if len(img.Links) > 0 {
		result.Links = make([]*images.ImageLink, len(img.Links))
		for i, l := range img.Links {
			result.Links[i] = &images.ImageLink{Title: l.Title, URL: l.URL}
		}
	}
	if img.DefaultCredentials != nil {
		result.DefaultCredentials = &images.ImageCredentials{
			Username: strPtr(img.DefaultCredentials.Username),
			Password: strPtr(img.DefaultCredentials.Password),
		}
	}
	if img.ProxyConfig != nil {
		result.ProxyConfig = &images.ImageProxyConfig{
			NeedsNoopSw:              img.ProxyConfig.NeedsNoOpSW,
			WebsocketPaths:           img.ProxyConfig.WebSocketPaths,
			RewriteHostAbsolutePaths: img.ProxyConfig.RewriteHostAbsolutePaths,
			CustomRequestHeaders:     img.ProxyConfig.CustomRequestHeaders,
			InjectBaseTag:            img.ProxyConfig.InjectBaseTag,
			TLSInsecure:              img.ProxyConfig.TLSInsecure,
			PreservePathPrefix:       img.ProxyConfig.PreservePathPrefix,
		}
	}
	return result
}

func strPtr(s string) *string {
	return &s
}

func boolPtr(b bool) *bool {
	return &b
}
