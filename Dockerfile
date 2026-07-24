FROM golang:1.26-alpine AS builder

WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -o kube-workspaces-api ./cmd/kube_workspaces/

FROM gcr.io/distroless/static:nonroot
LABEL org.opencontainers.image.source="https://github.com/kube-workspaces/api"
WORKDIR /
COPY --from=builder /workspace/kube-workspaces-api .
USER 65532:65532

ENTRYPOINT ["/kube-workspaces-api"]
CMD ["--domain", "0.0.0.0:8080"]
