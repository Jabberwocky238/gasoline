package common

import "testing"

func TestSHA224String(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"1507319881@qq.com", "b362d300c2e287dd2d858f1b77435786c2f326e109c337a8fdcbc66b"},
	}

	for _, tc := range testCases {
		result := SHA224String(tc.input)
		if result != tc.expected {
			t.Errorf("SHA224String(%q) = %q, 期望 %q", tc.input, result, tc.expected)
		}
	}
}
