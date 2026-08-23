package enrolltoken

import "testing"

func TestEncodeDecode_RoundTrips(t *testing.T) {
	want := Token{
		HubURL:      "https://192.0.2.10:8443",
		Fingerprint: "abcd1234",
		Secret:      "s3cr3t",
	}

	encoded, err := want.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	got, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got != want {
		t.Errorf("got %+v after round-trip, want %+v", got, want)
	}
}

func TestEncode_ProducesOneOpaqueString(t *testing.T) {
	encoded, err := Token{HubURL: "https://192.0.2.10:8443", Fingerprint: "abcd", Secret: "s"}.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// base64.RawURLEncoding: no '=' padding, no '/' or '+' - safe to
	// paste into a shell command or config value without quoting.
	for _, c := range encoded {
		if c == '=' || c == '/' || c == '+' {
			t.Errorf("encoded token contains %q, want URL-safe unpadded base64 only", c)
		}
	}
}

func TestDecode_RejectsGarbage(t *testing.T) {
	if _, err := Decode("not valid base64!!!"); err == nil {
		t.Fatal("expected an error decoding garbage input, got nil")
	}
}

func TestDecode_RejectsValidBase64ThatIsNotJSON(t *testing.T) {
	// "not json" base64-encoded, URL-safe, no padding.
	if _, err := Decode("bm90IGpzb24"); err == nil {
		t.Fatal("expected an error decoding valid base64 that isn't the expected JSON shape, got nil")
	}
}

func TestDecode_RejectsMissingFields(t *testing.T) {
	cases := []Token{
		{Fingerprint: "abcd", Secret: "s"},                       // missing HubURL
		{HubURL: "https://192.0.2.10:8443", Secret: "s"},         // missing Fingerprint
		{HubURL: "https://192.0.2.10:8443", Fingerprint: "abcd"}, // missing Secret
	}
	for _, c := range cases {
		encoded, err := c.Encode()
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		if _, err := Decode(encoded); err == nil {
			t.Errorf("Decode(%+v): expected an error for a missing field, got nil", c)
		}
	}
}
