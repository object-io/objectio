package objectio

import (
	"bytes"
	"net/http"
	"testing"
	"time"
)

// These vectors are shared verbatim with the Python SDK
// (sdk/python/tests/test_sigv4.py). Two implementations of the same algorithm
// drift silently; pinning both to the same bytes is what catches it.
const (
	testAccessKey = "AKIAEXAMPLE"
	testSecretKey = "secretkeyexample"
	testRegion    = "us-east-1"

	wantJSONPost = "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20260914/us-east-1/s3/aws4_request, " +
		"SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, " +
		"Signature=dba80b89d2f2e7762c8e8bb324eb9a214195dd4f46f1c23ded0cba0e3f1de1ff"

	wantAwkwardKeyGet = "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20260914/us-east-1/s3/aws4_request, " +
		"SignedHeaders=host;x-amz-content-sha256;x-amz-date, " +
		"Signature=551ff8cbf5e240b59d0db4470dbc862a781c9bb7295112ed76a64b961e863264"
)

func fixedTime() time.Time { return time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC) }

func TestSignJSONPost(t *testing.T) {
	body := []byte(`{"name":"ws-1","tenant":"platform"}`)
	req, err := http.NewRequest("POST", "https://s3.example.com/_admin/buckets", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	sign(req, testAccessKey, testSecretKey, testRegion, body, fixedTime())

	if got := req.Header.Get("Authorization"); got != wantJSONPost {
		t.Errorf("Authorization mismatch\n got %s\nwant %s", got, wantJSONPost)
	}
	if got := req.Header.Get("X-Amz-Date"); got != "20260914T120000Z" {
		t.Errorf("X-Amz-Date = %q", got)
	}
}

func TestSignPathWithSpaceAndHash(t *testing.T) {
	// The canonicalisation trap: the path that is signed and the path that is
	// sent must be the same spelling, or the server computes a different
	// signature and answers SignatureDoesNotMatch.
	raw := "/_admin/buckets/b/objects/q1 final#draft.txt"
	req, err := http.NewRequest("GET", "https://s3.example.com"+escapePath(raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	sign(req, testAccessKey, testSecretKey, testRegion, nil, fixedTime())

	if got := req.Header.Get("Authorization"); got != wantAwkwardKeyGet {
		t.Errorf("Authorization mismatch\n got %s\nwant %s", got, wantAwkwardKeyGet)
	}
}

func TestEscapePathKeepsSeparators(t *testing.T) {
	cases := map[string]string{
		"/_admin/buckets":                      "/_admin/buckets",
		"/a/b c":                               "/a/b%20c",
		"/a/b#c":                               "/a/b%23c",
		"/a/b+c":                               "/a/b%2Bc",
		"/a/~tilde":                            "/a/~tilde",
		"/_admin/buckets/b/objects/x/y/z.json": "/_admin/buckets/b/objects/x/y/z.json",
	}
	for in, want := range cases {
		if got := escapePath(in); got != want {
			t.Errorf("escapePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEscapeRFC3986UsesPercent20NotPlus(t *testing.T) {
	// url.QueryEscape would give "a+b", which SigV4 rejects.
	if got := escapeRFC3986("a b"); got != "a%20b" {
		t.Errorf("escapeRFC3986(%q) = %q", "a b", got)
	}
}

func TestEmptyBodyUsesTheKnownHash(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://s3.example.com/_admin/users", nil)
	sign(req, testAccessKey, testSecretKey, testRegion, nil, fixedTime())
	if got := req.Header.Get("X-Amz-Content-Sha256"); got != emptyPayloadHash {
		t.Errorf("X-Amz-Content-Sha256 = %q, want the empty-body constant", got)
	}
}

func TestCanonicalQuerySortsAndEscapes(t *testing.T) {
	q := map[string][]string{"b": {"2"}, "a": {"1"}, "c": {"x y"}}
	if got := canonicalQuery(q); got != "a=1&b=2&c=x%20y" {
		t.Errorf("canonicalQuery = %q", got)
	}
}
