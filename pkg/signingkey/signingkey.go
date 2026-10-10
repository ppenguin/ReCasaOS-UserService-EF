// Package signingkey keeps the key access and refresh tokens are signed with.
//
// The key was made at every start and held in memory only, while the refresh
// sessions it signs are tracked in the database: every restart (reboot, image
// update, backup stop) orphaned all sessions and signed everybody out. The key
// now lives next to the database it belongs to, under the same discipline as
// the bootstrap seal: regular file, mode 0600, owned by the service user, no
// symlinks, published atomically.
package signingkey

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/IceWhaleTech/CasaOS-Common/utils/jwt"
	"golang.org/x/sys/unix"
)

// Filename under the database directory.
const Filename = "user-service.key"

const maxKeyBytes = 4 << 10

// ErrUnsafe: the file exists but must not be trusted (owner, mode, symlink).
// The caller falls back to a key held in memory, as before.
var ErrUnsafe = errors.New("signing key file is unsafe")

// LoadOrCreate returns the key at path, making and publishing one when the file
// is absent or not a valid key (all sessions signed out once). An unsafe file is
// reported with ErrUnsafe and never replaced.
func LoadOrCreate(path string, ownerUID uint32) (*ecdsa.PrivateKey, bool, error) {
	if !filepath.IsAbs(path) {
		return nil, false, errors.New("signing key path must be absolute")
	}
	if err := checkDirectory(filepath.Dir(path), ownerUID); err != nil {
		return nil, false, err
	}
	key, err := load(path, ownerUID)
	switch {
	case err == nil:
		return key, false, nil
	case errors.Is(err, ErrUnsafe):
		return nil, false, err
	}
	// absent or unreadable as a key → a new one
	key, _, err = jwt.GenerateKeyPair()
	if err != nil {
		return nil, false, err
	}
	if err := publish(path, ownerUID, key); err != nil {
		return nil, false, err
	}
	return key, true, nil
}

func load(path string, ownerUID uint32) (*ecdsa.PrivateKey, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if err := checkFile(info, ownerUID); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: open: %v", ErrUnsafe, err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, fmt.Errorf("%w: changed while opening", ErrUnsafe)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxKeyBytes))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, errors.New("not a PEM EC private key")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func publish(path string, ownerUID uint32, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".user-service-key-*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	defer temporary.Close()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	// rename replaces an invalid key file; it never follows a symlink at path
	if err := os.Rename(temporary.Name(), path); err != nil {
		return err
	}
	handle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}

func checkFile(info os.FileInfo, ownerUID uint32) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%w: not a regular file", ErrUnsafe)
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("%w: mode %o, want 600", ErrUnsafe, info.Mode().Perm())
	}
	if uid, ok := ownerOf(info); !ok || uid != ownerUID {
		return fmt.Errorf("%w: unexpected owner", ErrUnsafe)
	}
	return nil
}

func checkDirectory(path string, ownerUID uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: directory is not a real directory", ErrUnsafe)
	}
	if uid, ok := ownerOf(info); !ok || uid != ownerUID {
		return fmt.Errorf("%w: directory has an unexpected owner", ErrUnsafe)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: directory writable by group or others", ErrUnsafe)
	}
	return nil
}

func ownerOf(info os.FileInfo) (uint32, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Uid, true
}
