# go-crypto

TOTP, bcrypt and random-generation helpers for Go projects, plus small wrappers for AES, PBKDF2 and UUID v4. Requires Go 1.25 (per `go.mod`).

## Installation

```bash
go get github.com/ralvarezdev/go-crypto
```

Direct dependencies: `go-strings` and `golang.org/x/crypto`.

## Packages

- **`go-crypto`** (package `gocrypto`) — `ErrFailedToHashPassword`, `ErrPasswordNotHashed`.
- **`aes`** — `EncryptGCM`, `DecryptGCM`, `EncryptCTR`, `DecryptCTR`; hex-encoded string output, pointer-to-string input/output. The key is passed to `aes.NewCipher`, so it must be a valid AES key length.
- **`bcrypt`** — `HashPassword(password, cost)`, `CompareHashAndPassword(hash, password)`, `IsHashed(str)`.
- **`otp/totp`** — `NewSecret`, `GenerateTOTPSha1`, `CompareTOTPSha1`, `ComputeHMAC`, `ComputeTimedHMAC`, `Truncate`, `NewURL` / `URL.Generate` (`otpauth://totp` links), `TestTOTPGenerator`.
- **`pbkdf2`** — `DeriveKey(password, salt, iterations, keyLength, hashFn)`.
- **`random/bytes`** — `Generate(length)`.
- **`random/strings`** — `Generate`, `GenerateN`, `GenerateAlphanumeric`, `GenerateNAlphanumeric`, `GenerateRecoveryCodes(count, length)`.
- **`uuid`** — `NewUUIDv4()`.

## Usage

```go
import (
    "time"

    "github.com/ralvarezdev/go-crypto/bcrypt"
    "github.com/ralvarezdev/go-crypto/otp/totp"
)

hash, err := bcrypt.HashPassword("my-password", 12)
ok := bcrypt.CompareHashAndPassword(hash, "my-password")

secret, err := totp.NewSecret(20)
code, err := totp.GenerateTOTPSha1(secret, time.Now(), 30, 6) // 30 s period, 6 digits
valid, err := totp.CompareTOTPSha1(code, secret, time.Now(), 30, 6)
```

## Development

```bash
go build ./...
go vet ./...
```

A `.golangci.yml` is included. There are no tests.

## License

GNU General Public License v3.0 (see [LICENSE](LICENSE)).
