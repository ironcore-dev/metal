FROM golang:1.22 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /metal
COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

COPY api/ api/
COPY client/ client/
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o metal cmd/main.go

FROM debian:bookworm-20240423-slim
WORKDIR /
USER 65532:65532
ENTRYPOINT ["/metal"]

COPY --from=builder /metal/metal .
