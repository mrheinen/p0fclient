package p0fclient

import (
	"net"
	"strings"
	"testing"
)

func TestP0fClientStart(t *testing.T) {
	for _, test := range []struct {
		description   string
		socketFile    string
		errorContains string
	}{
		{
			description:   "file does not exist",
			socketFile:    "/tmp/dsddsdsskdldewu89783jjkjjk",
			errorContains: "could not stat",
		},
		{
			description:   "file is not a socket",
			socketFile:    "/etc/hosts",
			errorContains: "could not open",
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			pc := NewP0fClient(test.socketFile)
			err := pc.Connect()

			if err == nil {
				if test.errorContains != "" {
					t.Errorf("expected error: %s, got nil", test.errorContains)
				}
				return
			}

			if !strings.Contains(err.Error(), test.errorContains) {
				t.Errorf("expected error: %s, to contain %s", err, test.errorContains)
			}
		})
	}
}

func TestP0fCreateQueryIPv4(t *testing.T) {
	for _, test := range []struct {
		description  string
		ip           string
		expectedType uint8
	}{
		{
			description:  "IPv4 address, OK",
			ip:           "127.0.0.1",
			expectedType: P0F_ADDR_IPV4,
		},
		{
			description:  "IPv6 address, OK",
			ip:           "::1",
			expectedType: P0F_ADDR_IPV6,
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			ip := net.ParseIP(test.ip)

			query, err := createQueryForIP(ip)
			if err != nil {
				t.Errorf("error creating query: %s", err)
			}

			if query.AddressType != test.expectedType {
				t.Errorf("expected type %d, got %d", test.expectedType, query.AddressType)
			}
		})
	}
}
