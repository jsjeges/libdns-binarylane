package binarylane

import (
	"context"
	"fmt"
	"strings"

	"github.com/digitalocean/godo"
)

// DefaultAPIBase is the root of Binary Lane's API. It deliberately excludes the
// "v2" version segment, which godo prefixes to each request path itself.
const DefaultAPIBase = "https://api.binarylane.com.au/"

// client returns a godo client pointed at Binary Lane, creating it on first
// use. Callers must hold p.mu.
func (p *Provider) client() (*godo.Client, error) {
	if p.godo != nil {
		return p.godo, nil
	}

	if strings.TrimSpace(p.APIToken) == "" {
		return nil, fmt.Errorf("binarylane: APIToken is required")
	}

	base := p.APIBase
	if base == "" {
		base = DefaultAPIBase
	}
	if !strings.HasSuffix(base, "/") {
		// godo resolves request paths relative to the base URL, so without a
		// trailing slash the final path segment would be discarded.
		base += "/"
	}

	c := godo.NewFromToken(p.APIToken)
	if err := godo.SetBaseURL(base)(c); err != nil {
		return nil, fmt.Errorf("binarylane: invalid APIBase %q: %w", p.APIBase, err)
	}

	p.godo = c

	return c, nil
}

// listRecords returns every record in the zone, following pagination.
func (p *Provider) listRecords(ctx context.Context, zone string) ([]godo.DomainRecord, error) {
	c, err := p.client()
	if err != nil {
		return nil, err
	}

	var (
		all []godo.DomainRecord
		opt = &godo.ListOptions{}
	)

	for {
		page, resp, err := c.Domains.Records(ctx, zone, opt)
		if err != nil {
			return nil, fmt.Errorf("binarylane: listing records for %q: %w", zone, err)
		}

		all = append(all, page...)

		if resp == nil || resp.Links == nil || resp.Links.IsLastPage() {
			break
		}

		current, err := resp.Links.CurrentPage()
		if err != nil {
			return nil, err
		}

		opt.Page = current + 1
	}

	return all, nil
}
