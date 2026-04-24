package mesh

import "testing"

func TestNormalizeTraversalEndpoint(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "stun:stun.l.google.com:19302", want: "stun.l.google.com:19302"},
		{input: "turn:turn.example.com:3478", want: "turn.example.com:3478"},
		{input: "stun://stun.cloudflare.com:3478", want: "stun.cloudflare.com:3478"},
		{input: "turn://relay.example.com:3478", want: "relay.example.com:3478"},
		{input: "  stun1.example.com:19302  ", want: "stun1.example.com:19302"},
	}

	for _, tt := range tests {
		if got := normalizeTraversalEndpoint(tt.input); got != tt.want {
			t.Fatalf("normalizeTraversalEndpoint(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
