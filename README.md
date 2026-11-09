# Binary Lane for `libdns`

[![godoc reference](https://img.shields.io/badge/godoc-reference-blue.svg)](https://pkg.go.dev/github.com/libdns/binarylane)

This package implements the [libdns](https://github.com/libdns/libdns) interfaces
for [Binary Lane](https://www.binarylane.com.au), an Australian cloud provider
whose DNS is managed through the Domains endpoints of its
[public API](https://api.binarylane.com.au/reference/).

## Authenticating

Create an API token in the Binary Lane control panel under **Account → API**,
and put it in `APIToken`.

## Example

```go
provider := binarylane.Provider{
	APIToken: os.Getenv("BINARYLANE_API_TOKEN"),
}

records, err := provider.GetRecords(context.TODO(), "example.com.")
```

## Why this uses DigitalOcean's client library

Binary Lane implements the same Domains API as DigitalOcean: the same paths, the
same record schema, and the same `{domain_records, links, meta}` pagination
envelope. Rather than duplicate an HTTP layer, this package drives
[`digitalocean/godo`](https://github.com/digitalocean/godo) with its base URL
pointed at Binary Lane.

`APIBase` overrides that URL if ever needed. Supply the API root only — the `v2`
version segment is added to each request path by `godo`, so including it here
would produce `/v2/v2/...`. A trailing slash is appended if absent, because
request paths are resolved relative to this URL.

## Supported record types

`A`, `AAAA`, `CAA`, `CNAME`, `MX`, `NS`, `SRV` and `TXT`.

Binary Lane keeps part of the RDATA of some types in dedicated API fields
(`priority`, `port`, `weight`, `flags`, `tag`) while libdns expects `Data` to
hold complete zone-file RDATA, so this package composes it on read and splits it
again on write. `TestRoundTrip` pins that behaviour.

Binary Lane also serves `SOA`, which libdns does not model. Those records are
returned as an opaque `libdns.RR` rather than being dropped, and are not
writable.

Binary Lane does not support `SVCB` or `HTTPS` records.

## Behaviour notes

- **Record identity.** `GetRecords` stores the provider's record ID in each
  record's `ProviderData` field. `DeleteRecords` uses it when present and falls
  back to matching by value otherwise, per the `libdns.RecordDeleter` rules
  (an empty `Type`, zero `TTL` or empty `Data` act as wildcards; `Name` is
  always significant).
- **Atomicity.** Binary Lane offers no batch endpoint, so `AppendRecords`,
  `SetRecords` and `DeleteRecords` are **not** atomic: if a call fails partway,
  earlier changes remain applied.
- **`SetRecords`** reuses existing records within an RRset where it can, so a
  record whose value is unchanged keeps its ID.

## Testing

`go test ./...` covers the conversion layer offline and needs no credentials.

The [`libdnstest`](https://github.com/libdns/libdns/tree/master/libdnstest)
conformance suite requires a live API token and a zone it may modify freely;
it is not wired into CI for that reason.
