package binarylane

import (
	"fmt"
	"strings"
	"time"

	"github.com/digitalocean/godo"
	"github.com/libdns/libdns"
)

// Binary Lane carries parts of the RDATA of some record types in dedicated
// fields (priority, port, weight, flags, tag) rather than in "data", while
// libdns expects Data to hold the full unescaped zone-file RDATA for every
// type. These helpers compose it on read and split it again on write.

// toLibdns converts an API record to its libdns representation, returning an
// RR-type-specific struct where libdns recognises the type and an opaque
// libdns.RR (with Error set) otherwise — for example SOA, which Binary Lane
// exposes but libdns does not model.
func toLibdns(rec godo.DomainRecord) libdns.Record {
	rr := libdns.RR{
		Name: rec.Name,
		Type: rec.Type,
		Data: rec.Data,
		TTL:  time.Duration(rec.TTL) * time.Second,
	}

	switch rec.Type {
	case "MX":
		rr.Data = fmt.Sprintf("%d %s", rec.Priority, rec.Data)
	case "SRV":
		rr.Data = fmt.Sprintf("%d %d %d %s", rec.Priority, rec.Weight, rec.Port, rec.Data)
	case "CAA":
		rr.Data = fmt.Sprintf("%d %s %q", rec.Flags, rec.Tag, rec.Data)
	}

	// A record this libdns version cannot parse into a typed struct is still
	// worth returning: callers listing a zone should not lose every record
	// because one is malformed or of an unmodelled type.
	parsed, err := rr.Parse()
	if err != nil {
		parsed = rr
	}

	return withRecordID(parsed, rec.ID)
}

// withRecordID stores the API's record ID in the record's ProviderData field so
// that SetRecords and DeleteRecords can address it without a lookup. The opaque
// libdns.RR has no such field, so unmodelled types are returned unchanged and
// are matched by value instead.
func withRecordID(rec libdns.Record, id int) libdns.Record {
	switch v := rec.(type) {
	case libdns.Address:
		v.ProviderData = id
		return v
	case libdns.CAA:
		v.ProviderData = id
		return v
	case libdns.CNAME:
		v.ProviderData = id
		return v
	case libdns.MX:
		v.ProviderData = id
		return v
	case libdns.NS:
		v.ProviderData = id
		return v
	case libdns.SRV:
		v.ProviderData = id
		return v
	case libdns.TXT:
		v.ProviderData = id
		return v
	default:
		return rec
	}
}

// recordID recovers an ID previously stored by withRecordID. ok is false for
// records the caller constructed itself, which must be matched by value.
func recordID(rec libdns.Record) (id int, ok bool) {
	var pd any

	switch v := rec.(type) {
	case libdns.Address:
		pd = v.ProviderData
	case libdns.CAA:
		pd = v.ProviderData
	case libdns.CNAME:
		pd = v.ProviderData
	case libdns.MX:
		pd = v.ProviderData
	case libdns.NS:
		pd = v.ProviderData
	case libdns.SRV:
		pd = v.ProviderData
	case libdns.TXT:
		pd = v.ProviderData
	default:
		return 0, false
	}

	id, ok = pd.(int)

	return id, ok && id != 0
}

// toAPI converts a libdns record into an API edit request, splitting the RDATA
// back out into the fields Binary Lane expects.
func toAPI(rec libdns.Record) (godo.DomainRecordEditRequest, error) {
	rr := rec.RR()

	req := godo.DomainRecordEditRequest{
		Type: rr.Type,
		Name: rr.Name,
		Data: rr.Data,
		TTL:  int(rr.TTL.Seconds()),
	}

	switch v := rec.(type) {
	case libdns.Address:
		// netip normalises the textual form, which the raw Data may not be.
		req.Data = v.IP.String()
	case libdns.MX:
		req.Priority = int(v.Preference)
		req.Data = v.Target
	case libdns.SRV:
		req.Priority = int(v.Priority)
		req.Weight = int(v.Weight)
		req.Port = int(v.Port)
		req.Data = v.Target
		// libdns splits the service and transport labels out of Name; the API
		// wants the single assembled owner name back.
		req.Name = strings.Trim(fmt.Sprintf("_%s._%s.%s", v.Service, v.Transport, v.Name), ".")
	case libdns.CAA:
		req.Flags = int(v.Flags)
		req.Tag = v.Tag
		req.Data = v.Value
	case libdns.TXT:
		// libdns hands us unquoted text and expects the implementation to do
		// whatever its API needs; Binary Lane stores the value verbatim.
		req.Data = v.Text
	}

	if req.Name == "" {
		req.Name = "@"
	}

	return req, nil
}

// sameRRset reports whether an API record belongs to the RRset identified by
// name and type.
func sameRRset(rec godo.DomainRecord, name, rrtype string) bool {
	return rec.Name == name && rec.Type == rrtype
}

// matches implements the partial-match rules of libdns.RecordDeleter: Name is
// always significant, while an empty Type, zero TTL or empty Data act as
// wildcards.
func matches(existing godo.DomainRecord, want libdns.RR) bool {
	if existing.Name != want.Name {
		return false
	}
	if want.Type != "" && existing.Type != want.Type {
		return false
	}
	if want.TTL != 0 && time.Duration(existing.TTL)*time.Second != want.TTL {
		return false
	}
	if want.Data != "" && toLibdns(existing).RR().Data != want.Data {
		return false
	}

	return true
}

// unFQDN trims the trailing dot from a zone name. The API does not use FQDNs.
func unFQDN(zone string) string {
	return strings.TrimSuffix(zone, ".")
}
