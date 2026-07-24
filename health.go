package kubeworkspaces

import (
	"context"

	health "github.com/kube-workspaces/api/gen/health"
	"goa.design/clue/log"
)

// health service implementation.
type healthsrvc struct{}

// NewHealth returns the health service implementation.
func NewHealth() health.Service {
	return &healthsrvc{}
}

// Health check endpoint
func (s *healthsrvc) Check(ctx context.Context) (res *health.CheckResult, err error) {
	log.Printf(ctx, "health.check")
	res = &health.CheckResult{
		Status: "ok",
	}
	return
}
