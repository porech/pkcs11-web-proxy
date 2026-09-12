package main

import (
	"crypto/tls"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func parseForTest(t *testing.T, args ...string) (string, options) {
	t.Helper()
	mode, opts, err := parseOptions(args, io.Discard)
	if err != nil {
		t.Fatalf("parseOptions(%v): %v", args, err)
	}
	return mode, opts
}

func TestModeDefaultsToProxySoExistingCommandLinesKeepWorking(t *testing.T) {
	mode, opts := parseForTest(t, "-destination-url", "https://example.test", "-pin", "1234")
	if mode != "proxy" {
		t.Fatalf("mode = %q, want \"proxy\"", mode)
	}
	if opts.DestinationURL != "https://example.test" {
		t.Fatalf("destination = %q", opts.DestinationURL)
	}
}

func TestModeIsTakenFromTheFirstArgumentWhenItNamesOne(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{args: []string{"proxy", "-destination-url", "https://example.test"}, want: "proxy"},
		{args: []string{"sign", "-certificate-index", "1"}, want: "sign"},
		{args: []string{"list-certificates"}, want: "list-certificates"},
		{args: []string{"-pin", "1234", "list-certificates"}, want: "list-certificates"},
	}
	for _, test := range tests {
		mode, _ := parseForTest(t, test.args...)
		if mode != test.want {
			t.Fatalf("%v: mode = %q, want %q", test.args, mode, test.want)
		}
	}
}

func TestSignModeRefusesProxyOnlyFlags(t *testing.T) {
	for _, args := range [][]string{
		{"sign", "-destination-url", "https://example.test"},
		{"sign", "-no-preserve-host"},
	} {
		if _, _, err := parseOptions(args, io.Discard); err == nil {
			t.Fatalf("%v was accepted", args)
		}
	}
}

func TestSignModeAcceptsTheListenerFlags(t *testing.T) {
	mode, opts := parseForTest(t, "sign", "-listen-port", "8081", "-listen-tls", "-listen-tls-cert", "c.pem", "-listen-tls-key", "k.pem")
	if mode != "sign" || opts.ListenPort != 8081 || !opts.ListenTLS {
		t.Fatalf("mode = %q, opts = %#v", mode, opts)
	}
}

func TestUnknownSubcommandIsRejected(t *testing.T) {
	if _, _, err := parseOptions([]string{"frobnicate"}, io.Discard); err == nil {
		t.Fatal("an unknown subcommand was accepted")
	}
}

func TestPinAndPinFileCannotBothBeGiven(t *testing.T) {
	if _, _, err := parseOptions([]string{"-pin", "1234", "-pin-file", "/tmp/pin"}, io.Discard); err == nil {
		t.Fatal("both pin and pin-file were accepted")
	}
}

func TestSelectCertificateRefusesAnIndexOutsideTheList(t *testing.T) {
	certificates := []tls.Certificate{{}, {}}
	for _, index := range []int{-1, 2, 99} {
		if _, err := selectCertificate(certificates, index); err == nil {
			t.Fatalf("index %d was accepted for a list of 2", index)
		}
	}
	if _, err := selectCertificate(certificates, 1); err != nil {
		t.Fatalf("index 1 was refused for a list of 2: %v", err)
	}
}

func TestValidateOptionsRequiresWhatEachModeNeeds(t *testing.T) {
	complete := options{PKCS11Path: "/lib/module.so", TokenSerial: "123", PIN: "1234", DestinationURL: "https://example.test"}

	tests := []struct {
		name    string
		mode    string
		mutate  func(*options)
		wantErr bool
	}{
		{name: "proxy is complete", mode: "proxy"},
		{name: "proxy without destination", mode: "proxy", mutate: func(o *options) { o.DestinationURL = "" }, wantErr: true},
		{name: "sign needs no destination", mode: "sign", mutate: func(o *options) { o.DestinationURL = "" }},
		{name: "no module path", mode: "sign", mutate: func(o *options) { o.PKCS11Path = "" }, wantErr: true},
		{name: "no token serial", mode: "sign", mutate: func(o *options) { o.TokenSerial = "" }, wantErr: true},
		{name: "no pin at all", mode: "sign", mutate: func(o *options) { o.PIN = "" }, wantErr: true},
		{name: "pin file instead of pin", mode: "sign", mutate: func(o *options) { o.PIN = ""; o.PINFile = "/tmp/pin" }},
		{name: "listen-tls without a certificate", mode: "sign", mutate: func(o *options) { o.ListenTLS = true }, wantErr: true},
		{name: "list-certificates needs no destination", mode: "list-certificates", mutate: func(o *options) { o.DestinationURL = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := complete
			if test.mutate != nil {
				test.mutate(&opts)
			}
			err := validateOptions(test.mode, opts)
			if test.wantErr && err == nil {
				t.Fatal("the options were accepted")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("the options were refused: %v", err)
			}
		})
	}
}

func TestReadPINFileDeletesTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pin")
	if err := os.WriteFile(path, []byte("  1234\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pin, err := readPINFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if pin != "1234" {
		t.Fatalf("pin = %q, want \"1234\"", pin)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("the PIN file still exists after being read")
	}
}
