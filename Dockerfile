# Build stage
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/Panchal-Sahil/cloudaudit/internal/cli.version=${VERSION}" \
    -o /cloudaudit ./cmd/cloudaudit

# Runtime stage: distroless/static ships CA certificates and a nonroot user
FROM gcr.io/distroless/static:nonroot
COPY --from=build /cloudaudit /cloudaudit
USER nonroot
ENTRYPOINT ["/cloudaudit"]
CMD ["scan"]
