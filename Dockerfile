# Dependencies are vendored, so the build needs no network access.
FROM docker.io/library/golang:1.26 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -mod=vendor -buildvcs=false -trimpath -ldflags="-s -w" -o /s3-key-portal . && \
    CGO_ENABLED=0 go build -mod=vendor -buildvcs=false -trimpath -ldflags="-s -w" -o /s3-zfs-helper ./cmd/s3-zfs-helper

# The ZFS helper runs on the host, not in a container. Get the binary with
#   podman build --target zfs-helper --output type=local,dest=out .
FROM scratch AS zfs-helper
COPY --from=build /s3-zfs-helper /s3-zfs-helper

FROM docker.io/library/alpine:3.24
COPY --from=build /s3-key-portal /usr/local/bin/s3-key-portal
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/s3-key-portal"]
