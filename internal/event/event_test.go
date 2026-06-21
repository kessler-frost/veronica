package event

import "testing"

func TestCommFromData(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{"present", `{"comm":"nginx","pid":42}`, "nginx"},
		{"missing", `{"pid":42}`, ""},
		{"empty_object", `{}`, ""},
		{"invalid_json", `not json`, ""},
		{"empty_string", ``, ""},
		{"wrong_type", `{"comm":123}`, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := CommFromData(tc.data); got != tc.want {
				t.Fatalf("CommFromData(%q) = %q, want %q", tc.data, got, tc.want)
			}
		})
	}
}

func TestPidFromData(t *testing.T) {
	tests := []struct {
		name string
		data string
		want uint32
	}{
		{"present", `{"comm":"nginx","pid":4521}`, 4521},
		{"missing", `{"comm":"nginx"}`, 0},
		{"zero", `{"pid":0}`, 0},
		{"invalid_json", `{bad`, 0},
		{"empty_string", ``, 0},
		{"max_uint32", `{"pid":4294967295}`, 4294967295},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := PidFromData(tc.data); got != tc.want {
				t.Fatalf("PidFromData(%q) = %d, want %d", tc.data, got, tc.want)
			}
		})
	}
}

func TestFilenameFromData(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{"present", `{"filename":"/etc/hosts","flags":1}`, "/etc/hosts"},
		{"missing", `{"comm":"vim"}`, ""},
		{"invalid_json", `<xml>`, ""},
		{"path_with_spaces", `{"filename":"/home/u/my file.txt"}`, "/home/u/my file.txt"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := FilenameFromData(tc.data); got != tc.want {
				t.Fatalf("FilenameFromData(%q) = %q, want %q", tc.data, got, tc.want)
			}
		})
	}
}

func TestFlagsFromData(t *testing.T) {
	tests := []struct {
		name string
		data string
		want int32
	}{
		{"rdonly", `{"flags":0}`, 0},
		{"wronly", `{"flags":1}`, 1},
		{"rdwr", `{"flags":2}`, 2},
		{"wronly_creat_trunc", `{"flags":577}`, 577},
		{"missing", `{"filename":"/etc/hosts"}`, 0},
		{"invalid_json", `oops`, 0},
		{"string_flags_is_zero", `{"flags":"1"}`, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := FlagsFromData(tc.data); got != tc.want {
				t.Fatalf("FlagsFromData(%q) = %d, want %d", tc.data, got, tc.want)
			}
		})
	}
}

func TestIsWriteOpen(t *testing.T) {
	// O_RDONLY=0, O_WRONLY=1, O_RDWR=2; the low two bits hold the access mode.
	tests := []struct {
		name  string
		flags int32
		want  bool
	}{
		{"rdonly", 0, false},
		{"wronly", 1, true},
		{"rdwr", 2, true},
		{"creat_only_no_write_mode", 0o100, false},               // O_CREAT alone is still O_RDONLY
		{"wronly_creat_trunc", 0o1101, true},                     // O_WRONLY|O_CREAT|O_TRUNC
		{"rdwr_append", 0o2 | 0o2000, true},                      // O_RDWR|O_APPEND
		{"rdonly_with_high_bits", 0o400000 /*O_DIRECTORY*/, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsWriteOpen(tc.flags); got != tc.want {
				t.Fatalf("IsWriteOpen(%#o) = %v, want %v", tc.flags, got, tc.want)
			}
		})
	}
}
