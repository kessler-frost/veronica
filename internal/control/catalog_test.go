package control

import "testing"

func TestCatalog(t *testing.T) {
	cat := Catalog()

	want := []string{"block-path-write", "block-mount", "block-egress", "block-exec", "drop-capability"}
	if len(cat) != len(want) {
		t.Fatalf("Catalog() = %d primitives, want %d", len(cat), len(want))
	}
	for _, id := range want {
		p, ok := cat[id]
		if !ok {
			t.Fatalf("Catalog() missing primitive %q", id)
		}
		if p.ID != id {
			t.Errorf("primitive %q has ID %q", id, p.ID)
		}
		if p.Desc == "" {
			t.Errorf("primitive %q has empty Desc", id)
		}
		if len(p.Hooks) == 0 {
			t.Errorf("primitive %q has no Hooks", id)
		}
		if p.Params == nil {
			t.Errorf("primitive %q has nil Params schema", id)
		}
	}
}

func TestValidateParams(t *testing.T) {
	tests := []struct {
		name      string
		primitive string
		params    map[string]any
		wantErr   bool
	}{
		{
			name:      "block-mount valid path_prefix",
			primitive: "block-mount",
			params:    map[string]any{"path_prefix": "/var/lib/docker/volumes"},
		},
		{
			name:      "block-mount empty params ok (path_prefix optional)",
			primitive: "block-mount",
			params:    map[string]any{},
		},
		{
			name:      "block-path-write valid",
			primitive: "block-path-write",
			params:    map[string]any{"path_prefix": "/etc"},
		},
		{
			name:      "block-path-write missing required path_prefix",
			primitive: "block-path-write",
			params:    map[string]any{},
			wantErr:   true,
		},
		{
			name:      "block-egress valid allow_cidrs",
			primitive: "block-egress",
			params:    map[string]any{"allow_cidrs": []any{"10.0.0.0/8", "192.168.0.0/16"}},
		},
		{
			name:      "block-egress missing required allow_cidrs",
			primitive: "block-egress",
			params:    map[string]any{},
			wantErr:   true,
		},
		{
			name:      "block-egress wrong type allow_cidrs (string not array)",
			primitive: "block-egress",
			params:    map[string]any{"allow_cidrs": "10.0.0.0/8"},
			wantErr:   true,
		},
		{
			name:      "block-egress array element wrong type",
			primitive: "block-egress",
			params:    map[string]any{"allow_cidrs": []any{"10.0.0.0/8", 42}},
			wantErr:   true,
		},
		{
			name:      "block-exec valid binaries",
			primitive: "block-exec",
			params:    map[string]any{"binaries": []any{"/usr/bin/curl"}},
		},
		{
			name:      "block-exec missing required binaries",
			primitive: "block-exec",
			params:    map[string]any{},
			wantErr:   true,
		},
		{
			name:      "drop-capability valid caps",
			primitive: "drop-capability",
			params:    map[string]any{"caps": []any{"CAP_NET_ADMIN"}},
		},
		{
			name:      "drop-capability missing required caps",
			primitive: "drop-capability",
			params:    map[string]any{},
			wantErr:   true,
		},
		{
			name:      "unknown primitive id",
			primitive: "block-everything",
			params:    map[string]any{},
			wantErr:   true,
		},
		{
			name:      "wrong-type path_prefix (number not string)",
			primitive: "block-mount",
			params:    map[string]any{"path_prefix": 1234},
			wantErr:   true,
		},
		{
			name:      "unexpected extra property rejected",
			primitive: "block-mount",
			params:    map[string]any{"path_prefix": "/x", "nonsense": true},
			wantErr:   true,
		},
		{
			name:      "nil params on optional-only primitive ok",
			primitive: "block-mount",
			params:    nil,
		},
		{
			name:      "nil params on required primitive rejected",
			primitive: "block-path-write",
			params:    nil,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateParams(tt.primitive, tt.params)
			if tt.wantErr && err == nil {
				t.Fatalf("ValidateParams(%q, %v) = nil, want error", tt.primitive, tt.params)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("ValidateParams(%q, %v) = %v, want nil", tt.primitive, tt.params, err)
			}
		})
	}
}
