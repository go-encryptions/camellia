<p align="center"><img src="https://raw.githubusercontent.com/go-encryptions/brand/main/social/go-encryptions.png" alt="go-encryptions/camellia" width="720"></p>

# go-encryptions/camellia

[![ci](https://github.com/go-encryptions/camellia/actions/workflows/ci.yml/badge.svg)](https://github.com/go-encryptions/camellia/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-encryptions/camellia.svg)](https://pkg.go.dev/github.com/go-encryptions/camellia)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD--3--Clause-blue.svg)](LICENSE)

Pure-Go **Camellia** block cipher (RFC 3713) as a standard `crypto/cipher.Block`: 16-byte blocks, 16-, 24- or 32-byte keys. Table-driven, no cgo, no dependency outside the standard library.

Its first consumer is [`go-fde/veracrypt`](https://github.com/go-fde/veracrypt), which needs Camellia in XTS mode with 256-bit keys (via [`go-encryptions/xts`](https://github.com/go-encryptions/xts)) to open VeraCrypt volumes.

## Install

```sh
go get github.com/go-encryptions/camellia
```

## Usage

```go
import "github.com/go-encryptions/camellia"

block, err := camellia.NewCipher(key) // 16, 24 or 32 bytes
if err != nil {
	// a camellia.KeySizeError for any other length
}
block.Encrypt(dst[:16], src[:16]) // dst and src may be the same slice
block.Decrypt(dst[:16], src[:16]) // a buffer under 16 bytes panics
```

The contract is that of `cipher.Block`: in-place operation is allowed and short buffers panic. `camellia.BlockSize` is 16.

## Byte order

Camellia is big-endian by specification: the key and the block are read as big-endian 64-bit words (the 24-byte key's `KR` is the last 8 bytes followed by their complement, as in RFC 3713 section 2.2). The ciphertext is therefore the same on every architecture; CI checks it on big-endian s390x.

## Verification

- RFC 3713 Appendix A: the three example vectors (128-, 192- and 256-bit keys), encrypted and decrypted.
- `testdata/botan-camellia.vec`: Botan's own `src/tests/data/block/camellia.vec`, 17 vectors (7 at 128 bits, 4 at 192, 6 at 256), encrypted and decrypted.
- `testdata/botan-diff.vec`: a differential corpus of 750 random keys and blocks (250 per key size, plus all-zero and all-one keys) generated from the Botan 3.14.1 command line by `internal/genbotan` (`go run ./internal/genbotan`). Regenerating needs `botan` on the `PATH`.
- `FuzzRoundTrip` cross-checks `Encrypt` and `Decrypt` round trips on every key length and the refusal of other lengths; CI runs it for 60 seconds, and its corpus is in `testdata/fuzz`.
- CI: race detector and a 100 % statement-coverage gate on amd64 and arm64; the same tests under QEMU on big-endian s390x and on riscv64; `govulncheck`.

I did not obtain the NESSIE Camellia vector files or the NTT specification itself, so no NESSIE vector is claimed beyond what Botan's file contains.

## Implementation

The structure follows RFC 3713: the key schedule of section 2.2 (KL, KR, KA, KB, the six Sigma constants, subkeys by rotation), the 18- or 24-round Feistel network with FL/FLINV every six rounds of section 2.3, and the F-function, FL and FLINV of section 2.4. `SBOX1` is the table of the RFC; `SBOX2`, `SBOX3`, `SBOX4` and the linear layer are folded at start-up into eight 256-entry `uint64` tables, so one F-function is eight look-ups and seven XORs. Decryption runs the same network over the reversed subkeys, as section 2.3.3 describes. Botan's `camellia.cpp` was read for the overall structure; Linux's GPL `camellia_generic.c` was not used.

Bibliography opened for this work: RFC 3713 (sections 2.2 to 2.4 and Appendix A); Botan `camellia.cpp` and `camellia.vec`.

## Performance

`BenchmarkEncrypt` and `BenchmarkDecrypt` loop the block over a 4 KiB buffer, the shape of one XTS sector, with a 256-bit key and no allocation. The reference is Botan 3.14.1 (`botan speed --buf-size=4096 Camellia-256`, wrapped as Go benchmarks by `internal/botanbench` so that `abbench` can interleave it). Apple M4 Max (arm64), one core (`GOMAXPROCS=1`), 6 interleaved rounds by `abbench --max-load 8`, compared with `benchstat`; every result file holds `^Benchmark` lines.

BENCHTABLE

Reproduce: `go test -c -o camellia.test .`, `go test -c -o botan.test ./internal/botanbench`, then `abbench --base ./camellia.test --head ./botan.test --max-load 8 -n 6 -- -test.bench . -test.run '^$'` (add `--head-arg=-botan.clear-cpuid=armv8aes` for the scalar column).

## License

BSD-3-Clause © the go-encryptions/camellia authors.
