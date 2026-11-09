package caddydns

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"github.com/jsjeges/libdns-binarylane"
)

func TestUnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantToken string
		wantBase  string
		wantErr   bool
	}{
		{
			name:      "inline token",
			input:     "binarylane abc123",
			wantToken: "abc123",
		},
		{
			name:      "block token",
			input:     "binarylane {\napi_token abc123\n}",
			wantToken: "abc123",
		},
		{
			name:      "block token and base",
			input:     "binarylane {\napi_token abc123\napi_base https://example.test/v2/\n}",
			wantToken: "abc123",
			wantBase:  "https://example.test/v2/",
		},
		{
			name:    "no token",
			input:   "binarylane",
			wantErr: true,
		},
		{
			name:    "token twice",
			input:   "binarylane abc123 {\napi_token def456\n}",
			wantErr: true,
		},
		{
			name:    "two inline args",
			input:   "binarylane abc123 def456",
			wantErr: true,
		},
		{
			name:    "unknown subdirective",
			input:   "binarylane {\napi_secret abc123\n}",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &Provider{new(binarylane.Provider)}
			d := caddyfile.NewTestDispenser(tc.input)

			err := p.UnmarshalCaddyfile(d)
			if tc.wantErr {
				if err == nil {
					t.Fatal("want error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if p.Provider.APIToken != tc.wantToken {
				t.Errorf("APIToken = %q, want %q", p.Provider.APIToken, tc.wantToken)
			}
			if p.Provider.APIBase != tc.wantBase {
				t.Errorf("APIBase = %q, want %q", p.Provider.APIBase, tc.wantBase)
			}
		})
	}
}

// The module must be registered under the ID Caddy's tls directive looks up,
// and New must hand back a usable provider rather than a nil embedded pointer.
func TestCaddyModule(t *testing.T) {
	info := Provider{}.CaddyModule()

	if got, want := string(info.ID), "dns.providers.binarylane"; got != want {
		t.Errorf("module ID = %q, want %q", got, want)
	}

	p, ok := info.New().(*Provider)
	if !ok {
		t.Fatalf("New returned %T, want *Provider", info.New())
	}
	if p.Provider == nil {
		t.Error("New returned a Provider with a nil embedded provider")
	}
}
