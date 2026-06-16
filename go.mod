module github.com/accretional/proto-ct

go 1.26

require (
	filippo.io/sunlight v0.8.0
	github.com/accretional/proto-domain v0.0.0-00010101000000-000000000000
	github.com/accretional/proto-ip v0.0.0-00010101000000-000000000000
	github.com/google/certificate-transparency-go v1.3.3
	golang.org/x/net v0.52.0
	golang.org/x/time v0.15.0
	google.golang.org/grpc v1.80.0
	google.golang.org/protobuf v1.36.11
	modernc.org/sqlite v1.51.0
)

// proto-domain itself has placeholder versions on its sibling-repo
// deps; we must replicate those replaces to resolve the module graph.
replace github.com/accretional/proto-domain => ../proto-domain

replace github.com/accretional/gluon => ../gluon

replace github.com/accretional/proto-ip => ../proto-ip

require (
	filippo.io/torchwood v0.8.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/crypto v0.49.0 // indirect
	golang.org/x/mod v0.33.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.44.0 // indirect
	golang.org/x/text v0.35.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260120221211-b8f7ae30c516 // indirect
	k8s.io/klog/v2 v2.130.1 // indirect
	modernc.org/libc v1.72.3 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)
