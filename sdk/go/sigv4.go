package objectio

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// AWS SigV4 for the S3 service, implemented against the standard library.
//
// Deliberately not aws-sdk-go-v2: this SDK is meant to sit inside a CSI
// driver or an operator, where pulling the AWS SDK in for one signing
// function is a large dependency for no gain. The algorithm is stable and
// ~80 lines.

const (
	algorithm  = "AWS4-HMAC-SHA256"
	terminator = "aws4_request"
	service    = "s3"
	// Every request signs its payload hash. S3 requires the header whether or
	// not there is a body; an empty body hashes to this constant.
	emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// escapePath percent-encodes a path the way SigV4 canonicalises it for S3:
// each segment escaped, the separators left alone, and — unlike the generic
// signer — no double encoding.
//
// The same function produces the URL that is sent and the canonical path that
// is signed. That is the whole point: a signature mismatch on an object key
// containing a space or a '#' is almost always the two disagreeing.
func escapePath(path string) string {
	segments := strings.Split(path, "/")
	for i, s := range segments {
		segments[i] = escapeRFC3986(s)
	}
	return strings.Join(segments, "/")
}

// escapeRFC3986 escapes everything outside the unreserved set. url.QueryEscape
// is not usable here: it encodes a space as '+', which SigV4 requires to be
// %20.
func escapeRFC3986(s string) string {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if strings.IndexByte(unreserved, c) >= 0 {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteString(strings.ToUpper(hex.EncodeToString([]byte{c})))
	}
	return b.String()
}

func canonicalQuery(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(q))
	for _, k := range keys {
		values := append([]string(nil), q[k]...)
		sort.Strings(values)
		for _, v := range values {
			parts = append(parts, escapeRFC3986(k)+"="+escapeRFC3986(v))
		}
	}
	return strings.Join(parts, "&")
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// sign adds the Authorization, X-Amz-Date and X-Amz-Content-Sha256 headers.
// `body` is the exact bytes that will be sent; pass nil for no body.
func sign(req *http.Request, accessKey, secretKey, region string, body []byte, now time.Time) {
	amzDate := now.UTC().Format("20060102T150405Z")
	dateStamp := now.UTC().Format("20060102")

	payloadHash := emptyPayloadHash
	if len(body) > 0 {
		payloadHash = sha256Hex(body)
	}

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	// Sign host, the two x-amz headers, and content-type when one is set.
	// Anything signed must also be sent, and anything sent that is signed must
	// not be rewritten in flight — which is why content-length is left out.
	signed := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	headers := map[string]string{
		"host":                 host,
		"x-amz-content-sha256": payloadHash,
		"x-amz-date":           amzDate,
	}
	if ct := req.Header.Get("Content-Type"); ct != "" {
		signed = append(signed, "content-type")
		headers["content-type"] = ct
	}
	sort.Strings(signed)

	var canonicalHeaders strings.Builder
	for _, h := range signed {
		canonicalHeaders.WriteString(h)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(strings.TrimSpace(headers[h]))
		canonicalHeaders.WriteByte('\n')
	}
	signedHeaders := strings.Join(signed, ";")

	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	canonicalRequest := strings.Join([]string{
		req.Method,
		path,
		canonicalQuery(req.URL.Query()),
		canonicalHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")

	credentialScope := strings.Join([]string{dateStamp, region, service, terminator}, "/")
	stringToSign := strings.Join([]string{
		algorithm,
		amzDate,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	key := hmacSHA256([]byte("AWS4"+secretKey), dateStamp)
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, service)
	key = hmacSHA256(key, terminator)
	signature := hex.EncodeToString(hmacSHA256(key, stringToSign))

	req.Header.Set("Authorization", algorithm+
		" Credential="+accessKey+"/"+credentialScope+
		", SignedHeaders="+signedHeaders+
		", Signature="+signature)
}
