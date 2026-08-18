package store

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// TestOpen_EnablesWALMode and TestOpen_SetsBusyTimeout mirror
// internal/hubstore's identically-named tests exactly - see that
// package's store_test.go for why these matter (SQLite's default
// journal mode and zero busy_timeout make one connection's write lock
// fail a concurrent writer immediately with SQLITE_BUSY rather than
// waiting for it).
func TestOpen_EnablesWALMode(t *testing.T) {
	st := openTestStore(t)

	var mode string
	if err := st.db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatalf("query journal_mode: %v", err)
	}
	if !strings.EqualFold(mode, "wal") {
		t.Errorf("got journal_mode %q, want \"wal\"", mode)
	}
}

func TestOpen_SetsBusyTimeout(t *testing.T) {
	st := openTestStore(t)

	var timeoutMS int
	if err := st.db.QueryRow(`PRAGMA busy_timeout`).Scan(&timeoutMS); err != nil {
		t.Fatalf("query busy_timeout: %v", err)
	}
	if timeoutMS != 5000 {
		t.Errorf("got busy_timeout %d, want 5000", timeoutMS)
	}
}

// TestOpen_ConcurrentWritesDontFailImmediately is the real-behavior proof,
// using two real goroutines against one real temp-file database - see
// internal/hubstore's identically-named test for the full rationale.
func TestOpen_ConcurrentWritesDontFailImmediately(t *testing.T) {
	st := openTestStore(t)

	const writesPerGoroutine = 25
	var wg sync.WaitGroup
	errs := make(chan error, 2*writesPerGoroutine)

	writer := func(prefix string) {
		defer wg.Done()
		for i := 0; i < writesPerGoroutine; i++ {
			name := fmt.Sprintf("%s-cert-%d", prefix, i)
			if _, err := st.GetOrCreateCertState(name); err != nil {
				errs <- err
				continue
			}
			if err := st.MarkIssued(name, time.Now(), time.Now().Add(24*time.Hour), "s1"); err != nil {
				errs <- err
			}
		}
	}

	wg.Add(2)
	go writer("a")
	go writer("b")
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent write failed (want busy_timeout to make it wait, not fail): %v", err)
	}
}

// TestGetAccount_UnknownReturnsErrNotFound and the certstate-level tests
// below give this package its first real test_test.go coverage at all -
// previously internal/store had zero test files (see ARCHITECTURE.md's
// Known gaps), verified only by running real binaries during development.
func TestGetAccount_UnknownReturnsErrNotFound(t *testing.T) {
	st := openTestStore(t)
	if _, err := st.GetAccount("https://example.com/dir"); !errors.Is(err, ErrNotFound) {
		t.Errorf("got error %v, want ErrNotFound", err)
	}
}
