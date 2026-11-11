package camellia

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
)

type vector struct{ key, in, out []byte }

// readVectors parses Botan's "Key = / In = / Out =" format. In and Out hold
// one or more consecutive 16-byte blocks, each enciphered independently (ECB).
func readVectors(t testing.TB, path string) []vector {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var vs []vector
	var cur vector
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		name, val, ok := strings.Cut(line, " = ")
		if !ok {
			continue
		}
		b, err := hex.DecodeString(val)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		switch name {
		case "Key":
			cur = vector{key: b}
		case "In":
			cur.in = b
		case "Out":
			cur.out = b
			vs = append(vs, cur)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return vs
}

func checkVectors(t *testing.T, path string, wantMin int) {
	vs := readVectors(t, path)
	if len(vs) < wantMin {
		t.Fatalf("%s: only %d vectors parsed, want at least %d", path, len(vs), wantMin)
	}
	sizes := map[int]int{}
	for _, v := range vs {
		sizes[len(v.key)]++
		c, err := NewCipher(v.key)
		if err != nil {
			t.Fatal(err)
		}
		if len(v.in)%16 != 0 || len(v.in) != len(v.out) {
			t.Fatalf("bad vector lengths %d/%d", len(v.in), len(v.out))
		}
		got := make([]byte, len(v.in))
		for i := 0; i < len(v.in); i += 16 {
			c.Encrypt(got[i:], v.in[i:])
		}
		if !bytes.Equal(got, v.out) {
			t.Fatalf("key %x: encrypt = %x, want %x", v.key, got, v.out)
		}
		for i := 0; i < len(v.in); i += 16 {
			c.Decrypt(got[i:], v.out[i:])
		}
		if !bytes.Equal(got, v.in) {
			t.Fatalf("key %x: decrypt = %x, want %x", v.key, got, v.in)
		}
	}
	t.Logf("%s: %d vectors, by key length %v", path, len(vs), sizes)
}

// Botan's src/tests/data/block/camellia.vec (it includes the RFC 3713 and
// NTT vectors); the sections are Camellia-128, -192 and -256.
func TestBotanVectors(t *testing.T) {
	checkVectors(t, "testdata/botan-camellia.vec", 17)
}

// RFC 3713, Appendix A.
func TestRFC3713(t *testing.T) {
	pt := "0123456789abcdeffedcba9876543210"
	for _, v := range []struct{ key, ct string }{
		{"0123456789abcdeffedcba9876543210", "67673138549669730857065648eabe43"},
		{"0123456789abcdeffedcba98765432100011223344556677", "b4993401b3e996f84ee5cee7d79b09b9"},
		{"0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff", "9acc237dff16d76c20ef7c919e3a7509"},
	} {
		key, _ := hex.DecodeString(v.key)
		in, _ := hex.DecodeString(pt)
		want, _ := hex.DecodeString(v.ct)
		c, err := NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 16)
		c.Encrypt(got, in)
		if !bytes.Equal(got, want) {
			t.Fatalf("%d-bit key: encrypt = %x, want %x", 8*len(key), got, want)
		}
		c.Decrypt(got, want)
		if !bytes.Equal(got, in) {
			t.Fatalf("%d-bit key: decrypt = %x, want %x", 8*len(key), got, in)
		}
	}
}

// Differential corpus produced by internal/genbotan from the installed
// `botan cipher` (Camellia-<bits>/CBC/NoPadding with a zero IV on one block).
func TestBotanDifferential(t *testing.T) {
	checkVectors(t, "testdata/botan-diff.vec", 600)
}

func TestKeySize(t *testing.T) {
	for n := 0; n <= 40; n++ {
		c, err := NewCipher(make([]byte, n))
		if n == 16 || n == 24 || n == 32 {
			if err != nil || c.BlockSize() != 16 {
				t.Fatalf("key %d: %v", n, err)
			}
			continue
		}
		var kse KeySizeError
		if c != nil || !errors.As(err, &kse) || int(kse) != n {
			t.Fatalf("key %d: got %v, %v", n, c, err)
		}
		if !strings.Contains(err.Error(), "invalid key size") {
			t.Fatal(err)
		}
	}
}

func TestPanics(t *testing.T) {
	c, _ := NewCipher(make([]byte, 16))
	for name, f := range map[string]func(){
		"enc short src": func() { c.Encrypt(make([]byte, 16), make([]byte, 15)) },
		"enc short dst": func() { c.Encrypt(make([]byte, 15), make([]byte, 16)) },
		"dec short src": func() { c.Decrypt(make([]byte, 16), make([]byte, 15)) },
		"dec short dst": func() { c.Decrypt(make([]byte, 15), make([]byte, 16)) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", name)
				}
			}()
			f()
		}()
	}
}

func TestInPlace(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	c, _ := NewCipher(key)
	pt := []byte("sixteen byte blk")
	want := make([]byte, 16)
	c.Encrypt(want, pt)
	buf := append([]byte(nil), pt...)
	c.Encrypt(buf, buf)
	if !bytes.Equal(buf, want) {
		t.Fatal("in-place encrypt differs")
	}
	c.Decrypt(buf, buf)
	if !bytes.Equal(buf, pt) {
		t.Fatal("in-place decrypt differs")
	}
}

func roundTrip(t testing.TB, c cipher.Block, p []byte) {
	ct := make([]byte, 16)
	c.Encrypt(ct, p)
	back := make([]byte, 16)
	c.Decrypt(back, ct)
	if !bytes.Equal(back, p) {
		t.Fatalf("round trip failed: %x -> %x -> %x", p, ct, back)
	}
}

func FuzzRoundTrip(f *testing.F) {
	f.Add(make([]byte, 16), make([]byte, 16))
	f.Add(make([]byte, 24), []byte("0123456789abcdef"))
	f.Add(bytes.Repeat([]byte{0xff}, 32), bytes.Repeat([]byte{0xa5}, 16))
	f.Fuzz(func(t *testing.T, key, block []byte) {
		if len(block) < 16 {
			return
		}
		c, err := NewCipher(key)
		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			if err == nil {
				t.Fatal("bad key accepted")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		roundTrip(t, c, block[:16])
		// Encrypt must be a function of the block alone.
		a, b := make([]byte, 16), make([]byte, 16)
		c.Encrypt(a, block[:16])
		c.Encrypt(b, block[:16])
		if !bytes.Equal(a, b) {
			t.Fatal("encrypt not deterministic")
		}
	})
}

func benchBlock(b *testing.B, dec bool) {
	c, _ := NewCipher(bytes.Repeat([]byte{7}, 32))
	buf := make([]byte, 4096)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for o := 0; o < len(buf); o += 16 {
			if dec {
				c.Decrypt(buf[o:o+16], buf[o:o+16])
			} else {
				c.Encrypt(buf[o:o+16], buf[o:o+16])
			}
		}
	}
}

func BenchmarkEncrypt(b *testing.B) { benchBlock(b, false) }
func BenchmarkDecrypt(b *testing.B) { benchBlock(b, true) }
