package control

import "testing"

func TestEvaluateKernelSupport(t *testing.T) {
	tests := []struct {
		name         string
		configured   bool
		active       bool
		wantReady    bool
		wantReasonOn bool // expect a non-empty Reason
	}{
		{"both present", true, true, true, false},
		{"config only", true, false, false, true},
		{"active only", false, true, false, true},
		{"neither", false, false, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks := evaluateKernelSupport(tt.configured, tt.active)
			if ks.EnforceReady != tt.wantReady {
				t.Errorf("EnforceReady = %v, want %v", ks.EnforceReady, tt.wantReady)
			}
			if (ks.Reason != "") != tt.wantReasonOn {
				t.Errorf("Reason = %q, want non-empty=%v", ks.Reason, tt.wantReasonOn)
			}
			if ks.BPFLSMConfigured != tt.configured || ks.BPFInActiveLSM != tt.active {
				t.Errorf("raw flags not preserved: %+v", ks)
			}
		})
	}
}
