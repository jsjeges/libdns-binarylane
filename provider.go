// Package binarylane implements the libdns interfaces for Binary Lane
// (https://www.binarylane.com.au), an Australian cloud provider whose DNS
// service is reachable through the Domains endpoints of its public API.
//
// Binary Lane implements the same Domains API as DigitalOcean — identical
// paths, record schema and pagination envelope — so this package drives it
// with DigitalOcean's own client library pointed at a different host rather
// than duplicating an HTTP layer.
package binarylane

import (
	"context"
	"fmt"
	"sync"

	"github.com/digitalocean/godo"
	"github.com/libdns/libdns"
)

// Provider implements the libdns interfaces for Binary Lane.
type Provider struct {
	// APIToken is a Binary Lane API token, created under Account → API in the
	// Binary Lane control panel. Required.
	APIToken string `json:"api_token,omitempty"`

	// APIBase optionally overrides the API root. Supply the root only: the
	// "v2" version segment is added to each request path automatically, so
	// including it here would produce "/v2/v2/...". A trailing slash is added
	// if absent. Defaults to DefaultAPIBase.
	APIBase string `json:"api_base,omitempty"`

	godo *godo.Client
	mu   sync.Mutex
}

// GetRecords lists all the records in the zone.
//
// Records of types libdns does not model — Binary Lane also serves SOA — are
// returned as opaque libdns.RR values.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	api, err := p.listRecords(ctx, unFQDN(zone))
	if err != nil {
		return nil, err
	}

	recs := make([]libdns.Record, 0, len(api))
	for _, rec := range api {
		recs = append(recs, toLibdns(rec))
	}

	return recs, nil
}

// AppendRecords creates the given records in the zone and returns them. It
// never modifies an existing record.
//
// Binary Lane offers no batch endpoint, so this is not atomic: if a later
// record fails, earlier ones remain created.
func (p *Provider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	c, err := p.client()
	if err != nil {
		return nil, err
	}

	zone = unFQDN(zone)

	created := make([]libdns.Record, 0, len(recs))
	for _, rec := range recs {
		req, err := toAPI(rec)
		if err != nil {
			return created, err
		}

		out, _, err := c.Domains.CreateRecord(ctx, zone, &req)
		if err != nil {
			return created, fmt.Errorf("binarylane: creating %s record %q: %w", req.Type, req.Name, err)
		}

		created = append(created, toLibdns(*out))
	}

	return created, nil
}

// SetRecords makes the records in the zone match the input: for every (name,
// type) pair present in recs, the records given are afterwards the only
// members of that RRset. Other RRsets are untouched.
//
// Existing records are reused where an RRset shrinks or grows, so an unchanged
// record keeps its identity. Binary Lane offers no batch endpoint, so this is
// not atomic.
func (p *Provider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	c, err := p.client()
	if err != nil {
		return nil, err
	}

	zone = unFQDN(zone)

	existing, err := p.listRecords(ctx, zone)
	if err != nil {
		return nil, err
	}

	// Group the input into RRsets, preserving the order they arrived in so the
	// returned slice is predictable.
	type key struct{ name, rrtype string }

	var order []key
	groups := map[key][]libdns.Record{}

	for _, rec := range recs {
		req, err := toAPI(rec)
		if err != nil {
			return nil, err
		}

		k := key{req.Name, req.Type}
		if _, seen := groups[k]; !seen {
			order = append(order, k)
		}

		groups[k] = append(groups[k], rec)
	}

	var result []libdns.Record

	for _, k := range order {
		want := groups[k]

		var have []godo.DomainRecord
		for _, rec := range existing {
			if sameRRset(rec, k.name, k.rrtype) {
				have = append(have, rec)
			}
		}

		for i, rec := range want {
			req, err := toAPI(rec)
			if err != nil {
				return result, err
			}

			if i < len(have) {
				out, _, err := c.Domains.EditRecord(ctx, zone, have[i].ID, &req)
				if err != nil {
					return result, fmt.Errorf("binarylane: updating %s record %q: %w", req.Type, req.Name, err)
				}

				result = append(result, toLibdns(*out))

				continue
			}

			out, _, err := c.Domains.CreateRecord(ctx, zone, &req)
			if err != nil {
				return result, fmt.Errorf("binarylane: creating %s record %q: %w", req.Type, req.Name, err)
			}

			result = append(result, toLibdns(*out))
		}

		// Anything left over in the RRset is surplus to the input.
		for _, surplus := range have[min(len(want), len(have)):] {
			if _, err := c.Domains.DeleteRecord(ctx, zone, surplus.ID); err != nil {
				return result, fmt.Errorf("binarylane: deleting surplus %s record %q: %w", surplus.Type, surplus.Name, err)
			}
		}
	}

	return result, nil
}

// DeleteRecords deletes records from the zone, returning those actually
// deleted. Records that do not exist are silently ignored.
//
// A record carrying an ID from GetRecords is deleted directly. Otherwise it is
// matched by value, where an empty Type, zero TTL or empty Data act as
// wildcards and Name is always significant.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	c, err := p.client()
	if err != nil {
		return nil, err
	}

	zone = unFQDN(zone)

	existing, err := p.listRecords(ctx, zone)
	if err != nil {
		return nil, err
	}

	byID := make(map[int]godo.DomainRecord, len(existing))
	for _, rec := range existing {
		byID[rec.ID] = rec
	}

	var deleted []libdns.Record

	for _, rec := range recs {
		var targets []godo.DomainRecord

		if id, ok := recordID(rec); ok {
			if found, live := byID[id]; live {
				targets = []godo.DomainRecord{found}
			}
		} else {
			for _, candidate := range existing {
				if matches(candidate, rec.RR()) {
					targets = append(targets, candidate)
				}
			}
		}

		for _, target := range targets {
			if _, err := c.Domains.DeleteRecord(ctx, zone, target.ID); err != nil {
				return deleted, fmt.Errorf("binarylane: deleting %s record %q: %w", target.Type, target.Name, err)
			}

			delete(byID, target.ID)
			deleted = append(deleted, toLibdns(target))
		}
	}

	return deleted, nil
}

// ListZones returns the domains available to the API token.
func (p *Provider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	c, err := p.client()
	if err != nil {
		return nil, err
	}

	var (
		zones []libdns.Zone
		opt   = &godo.ListOptions{}
	)

	for {
		page, resp, err := c.Domains.List(ctx, opt)
		if err != nil {
			return nil, fmt.Errorf("binarylane: listing domains: %w", err)
		}

		for _, d := range page {
			zones = append(zones, libdns.Zone{Name: libdns.AbsoluteName(d.Name, ".")})
		}

		if resp == nil || resp.Links == nil || resp.Links.IsLastPage() {
			break
		}

		current, err := resp.Links.CurrentPage()
		if err != nil {
			return nil, err
		}

		opt.Page = current + 1
	}

	return zones, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
	_ libdns.ZoneLister     = (*Provider)(nil)
)
