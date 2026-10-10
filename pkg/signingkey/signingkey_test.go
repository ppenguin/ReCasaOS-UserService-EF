package signingkey

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func setup(t *testing.T) (string, uint32) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "db")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, Filename), uint32(os.Geteuid())
}

func TestKeySurvivesARestart(t *testing.T) {
	path, uid := setup(t)
	first, created, err := LoadOrCreate(path, uid)
	if err != nil || !created {
		t.Fatalf("first start: created=%v err=%v", created, err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v mode %v", err, info.Mode())
	}
	second, created, err := LoadOrCreate(path, uid)
	if err != nil || created || !first.Equal(second) {
		t.Fatalf("restart: created=%v err=%v same=%v", created, err, first.Equal(second))
	}
}

func TestInvalidKeyIsReplaced(t *testing.T) {
	path, uid := setup(t)
	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	key, created, err := LoadOrCreate(path, uid)
	if err != nil || !created || key == nil {
		t.Fatalf("created=%v err=%v", created, err)
	}
	if again, _, err := LoadOrCreate(path, uid); err != nil || !key.Equal(again) {
		t.Fatalf("replacement not persisted: %v", err)
	}
}

func TestUnsafeFilesAreRefusedAndKept(t *testing.T) {
	for name, prepare := range map[string]func(t *testing.T, path string){
		"world readable": func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"symlink": func(t *testing.T, path string) {
			target := filepath.Join(t.TempDir(), "elsewhere")
			if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			path, uid := setup(t)
			prepare(t, path)
			before, _ := os.Lstat(path)
			if _, _, err := LoadOrCreate(path, uid); !errors.Is(err, ErrUnsafe) {
				t.Fatalf("err = %v, want ErrUnsafe", err)
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) {
				t.Fatal("unsafe file was replaced")
			}
		})
	}
}

func TestUnsafeDirectoryIsRefused(t *testing.T) {
	path, uid := setup(t)
	if err := os.Chmod(filepath.Dir(path), 0o777); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreate(path, uid); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("err = %v, want ErrUnsafe", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("key written into a group/world-writable directory")
	}
}
