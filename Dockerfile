# Dependencies are vendored, so the build needs no network access.
FROM docker.io/library/golang:1.26 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -mod=vendor -buildvcs=false -trimpath -ldflags="-s -w" -o /versity-s3-portal . && \
    CGO_ENABLED=0 go build -mod=vendor -buildvcs=false -trimpath -ldflags="-s -w" -o /s3-zfs-helper ./cmd/s3-zfs-helper && \
    CGO_ENABLED=0 go build -mod=vendor -buildvcs=false -trimpath -ldflags="-s -w" -o /s3-zfs-mounter ./cmd/s3-zfs-mounter

# The ZFS helper and its mounter run on the host, not in a container. Get
# the binaries with
#   podman build --target zfs-helper --output type=local,dest=out .
FROM scratch AS zfs-helper
COPY --from=build /s3-zfs-helper /s3-zfs-helper
COPY --from=build /s3-zfs-mounter /s3-zfs-mounter

FROM docker.io/library/alpine:3.24
COPY --from=build /versity-s3-portal /usr/local/bin/versity-s3-portal
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/versity-s3-portal"]
