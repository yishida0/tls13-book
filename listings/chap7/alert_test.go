package tls13

import (
	"bytes"
	"strings"
	"testing"
)

func TestAlertMarshal(t *testing.T) {
	tests := []struct {
		alert alert
		want  []byte
	}{
		{alert{level: alertLevelWarning, description: closeNotify}, []byte{1, 0}},
		{alert{level: 2, description: 40}, []byte{2, 40}},
	}
	for _, tt := range tests {
		if got := tt.alert.marshal(); !bytes.Equal(got, tt.want) {
			t.Errorf("Marshal(%+v) = %v, want %v", tt.alert, got, tt.want)
		}
	}
}

func TestAlertUnmarshal(t *testing.T) {
	alert, err := unmarshalAlert([]byte{2, 42})
	if err != nil {
		t.Fatalf("UnmarshalAlert: %v", err)
	}
	if alert.level != 2 || alert.description != 42 {
		t.Errorf("UnmarshalAlert = %+v, want level 2, description 42", alert)
	}
	if got := alert.marshal(); !bytes.Equal(got, []byte{2, 42}) {
		t.Errorf("round trip = %v, want [2 42]", got)
	}
}

func TestAlertUnmarshalRejectsMalformed(t *testing.T) {
	for _, payload := range [][]byte{nil, {1}, {1, 0, 0}} {
		if _, err := unmarshalAlert(payload); err == nil {
			t.Errorf("UnmarshalAlert(%v) succeeded, want error", payload)
		}
	}
}

func TestAlertError(t *testing.T) {
	var err error = &alert{level: 2, description: 40}
	msg := err.Error()
	if !strings.Contains(msg, "level 2") || !strings.Contains(msg, "description 40") {
		t.Errorf("Error() = %q, want it to mention level 2 and description 40", msg)
	}
}
