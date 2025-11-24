# Create a dedicated unprivileged host user for torgo escapes
sudo adduser --system --no-create-home --uid 9999 torgo-isolated

# If your distro blocks unprivileged userns (Ubuntu, Debian), allow it:
echo "kernel.unprivileged_userns_clone=1" | sudo tee /etc/sysctl.d/99-torgo.conf
sudo sysctl -p /etc/sysctl.d/99-torgo.conf


##build
GOOS=linux GOARCH=arm64 CGO_ENABLED=1 \
go build -trimpath -mod=readonly \
-ldflags="-s -w -extldflags=-static -buildid=" \
-tags netgo,osusergo \
-o torgo ./cmd/torgo && \
strip --strip-all torgo && \
upx --best --lzma torgo 2>/dev/null || true && \
echo "FINAL BINARY READY:" && ls -lh torgo