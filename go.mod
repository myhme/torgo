module torgo

go 1.24

require (
	github.com/miekg/dns v1.1.66
	golang.org/x/net v0.41.0
)

require (
	golang.org/x/mod v0.25.0 // indirect
	golang.org/x/sync v0.15.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/tools v0.34.0 // indirect
)

// Indirect dependencies will be updated by 'go mod tidy'
// For example, golang.org/x/sys and golang.org/x/text are often
// indirect dependencies of golang.org/x/net or other packages.
// Running `go mod tidy` will ensure your go.sum is also updated
// and that the versions of indirect dependencies are consistent.
