module torgo

go 1.21

require (
	github.com/miekg/dns v1.1.66
	golang.org/x/net v0.40.0
)

require (
	golang.org/x/mod v0.24.0 // indirect
	golang.org/x/sync v0.13.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/tools v0.32.0 // indirect
)

// Indirect dependencies will be updated by 'go mod tidy'
// For example, golang.org/x/sys and golang.org/x/text are often
// indirect dependencies of golang.org/x/net or other packages.
// Running `go mod tidy` will ensure your go.sum is also updated
// and that the versions of indirect dependencies are consistent.
