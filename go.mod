module torgo

go 1.25.0

toolchain go1.25.3

require (
	github.com/miekg/dns v1.1.68
	golang.org/x/net v0.46.0
)

require (
	golang.org/x/mod v0.29.0 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
	golang.org/x/tools v0.38.0 // indirect
)

// Indirect dependencies will be updated by 'go mod tidy'
// For example, golang.org/x/sys and golang.org/x/text are often
// indirect dependencies of golang.org/x/net or other packages.
// Running `go mod tidy` will ensure your go.sum is also updated
// and that the versions of indirect dependencies are consistent.
