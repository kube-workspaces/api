// Package proxy implements HTTP reverse proxying to workspace pods.
// It handles routing requests to specific workspace containers,
// supporting both standard HTTP requests and WebSocket upgrades
// for terminal access and other real-time communication.
package proxy
