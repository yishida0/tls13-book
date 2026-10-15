package tls13

import (
	"errors"
	"fmt"
)

type alert struct {
	level       uint8
	description alertDescription
}

func (a *alert) Error() string {
	return fmt.Sprintf("tls13: received alert: level %d, description %d", a.level, a.description)
}

func (a *alert) marshal() []byte {
	return []byte{a.level, byte(a.description)}
}

func unmarshalAlert(payload []byte) (*alert, error) {
	if len(payload) != 2 {
		return nil, errors.New("tls13: malformed alert")
	}
	return &alert{level: payload[0], description: alertDescription(payload[1])}, nil
}
