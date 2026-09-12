module github.com/ridiculouspickles/pickles-push

// Pinned, and the pin is load-bearing for more than the language level
// (pickles-email#526). Each relay builds on its own host, so each inherited whatever Go
// that host happened to have: site A was built with 1.26.7 and site B with 1.24.4, which
// is genuinely inside the stdlib advisories an SCA lists. A `toolchain` line makes the
// build fetch this one rather than use an older local one, and makes the two sites agree.
//
// An SCA reads the `go` directive as the version in use, so a stale one prints a page of
// stdlib CVEs whatever the binary was really built with. `runtime.Version()` is in the
// startup log so the deployed answer can be read back rather than inferred.
go 1.26

toolchain go1.26.8
