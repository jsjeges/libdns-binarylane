// Package caddydns registers the Binary Lane libdns provider as a Caddy DNS
// module, so Caddy can solve ACME DNS-01 challenges in a Binary Lane zone.
//
// It is a separate Go module from the provider itself: the provider depends on
// nothing but libdns, and nothing that imports it should have to pull in Caddy.
package caddydns

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"github.com/jsjeges/libdns-binarylane"
)

// Provider wraps the provider implementation as a Caddy module.
type Provider struct{ *binarylane.Provider }

func init() {
	caddy.RegisterModule(Provider{})
}

// CaddyModule returns the Caddy module information.
func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.binarylane",
		New: func() caddy.Module { return &Provider{new(binarylane.Provider)} },
	}
}

// Provision resolves placeholders in the config before it is used, which is
// how the API token arrives from an environment variable rather than being
// written into the Caddyfile. Implements caddy.Provisioner.
func (p *Provider) Provision(ctx caddy.Context) error {
	repl := caddy.NewReplacer()
	p.Provider.APIToken = repl.ReplaceAll(p.Provider.APIToken, "")
	p.Provider.APIBase = repl.ReplaceAll(p.Provider.APIBase, "")
	return nil
}

// UnmarshalCaddyfile sets up the DNS provider from Caddyfile tokens. Syntax:
//
//	binarylane [<api_token>] {
//	    api_token <api_token>
//	    api_base  <url>
//	}
func (p *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			p.Provider.APIToken = d.Val()
		}
		if d.NextArg() {
			return d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "api_token":
				if p.Provider.APIToken != "" {
					return d.Err("API token already set")
				} else if d.NextArg() {
					p.Provider.APIToken = d.Val()
				} else {
					return d.ArgErr()
				}
			case "api_base":
				if p.Provider.APIBase != "" {
					return d.Err("API base already set")
				} else if d.NextArg() {
					p.Provider.APIBase = d.Val()
				} else {
					return d.ArgErr()
				}
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}
	if p.Provider.APIToken == "" {
		return d.Err("missing API token")
	}
	return nil
}

// Interface guards
var (
	_ caddyfile.Unmarshaler = (*Provider)(nil)
	_ caddy.Provisioner     = (*Provider)(nil)
)
