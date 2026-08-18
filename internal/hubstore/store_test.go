package hubstore

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// oldV1Schema is exactly what schema.sql looked like before
// consecutive_failures/last_success_at were added, kept as a literal here
// (not read from git history) so this test doesn't depend on anything
// outside itself to construct a realistic pre-migration database.
const oldV1Schema = `
CREATE TABLE schema_meta (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL
);
INSERT INTO schema_meta (id, version) VALUES (1, 1);

CREATE TABLE spoke_cert_state (
    spoke_id         TEXT NOT NULL,
    name             TEXT NOT NULL,
    not_before       TIMESTAMP,
    not_after        TIMESTAMP,
    serial_number    TEXT,
    status           TEXT NOT NULL DEFAULT 'unknown'
                         CHECK (status IN ('unknown', 'active', 'failed')),
    last_checkin_at  TIMESTAMP,
    last_error       TEXT,
    PRIMARY KEY (spoke_id, name)
);
`

// TestOpen_MigratesExistingV1Database proves Open brings a database created
// under the pre-consecutive_failures/last_success_at schema up to date
// in place, without losing whatever it already held — this is the first
// real schema migration this project has ever needed, and the untested
// path (a brand-new database, where CREATE TABLE IF NOT EXISTS alone is
// sufficient) is not the one that matters here.
func TestOpen_MigratesExistingV1Database(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v1.db")

	seed, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open for seeding: %v", err)
	}
	if _, err := seed.Exec(oldV1Schema); err != nil {
		t.Fatalf("create v1 schema: %v", err)
	}
	if _, err := seed.Exec(
		`INSERT INTO spoke_cert_state (spoke_id, name, status, serial_number) VALUES ('spoke-a', 'cert-a', 'active', 'pre-migration-serial')`,
	); err != nil {
		t.Fatalf("seed pre-migration row: %v", err)
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("close seed connection: %v", err)
	}

	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open on a v1 database: %v", err)
	}
	defer st.Close()

	var version int
	if err := st.db.QueryRow(`SELECT version FROM schema_meta WHERE id = 1`).Scan(&version); err != nil {
		t.Fatalf("read schema version after migration: %v", err)
	}
	if version != currentSchemaVersion {
		t.Errorf("got schema version %d after migration, want %d", version, currentSchemaVersion)
	}

	// The pre-existing row must survive with its real data intact, and the
	// new columns must exist with sane defaults - not just "the migration
	// didn't error," but "a query using the new columns actually works
	// against a row that predates them."
	cs, err := st.Get("spoke-a", "cert-a")
	if err != nil {
		t.Fatalf("Get pre-migration row after migration: %v", err)
	}
	if cs.SerialNumber.String != "pre-migration-serial" {
		t.Errorf("got serial %q, want the pre-migration row's original %q", cs.SerialNumber.String, "pre-migration-serial")
	}
	if cs.ConsecutiveFailures != 0 {
		t.Errorf("got consecutive_failures %d for a pre-migration row, want default 0", cs.ConsecutiveFailures)
	}
	if cs.LastSuccessAt.Valid {
		t.Error("got a non-null last_success_at for a pre-migration row that never went through CheckinActive")
	}

	// And the new methods must actually work against this migrated table,
	// not just report plausible-looking defaults from Get.
	if err := st.CheckinFailed("spoke-a", "cert-a", nil, 1); err != nil {
		t.Fatalf("CheckinFailed against a migrated table: %v", err)
	}
}

// TestOpen_IdempotentOnCurrentDatabase proves migrate is safe to run every
// process start, including against a database already at the current
// version - not just once, on first upgrade.
func TestOpen_IdempotentOnCurrentDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "current.db")

	st1, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if err := st1.CheckinActive("spoke-a", "cert-a", time.Now(), time.Now().Add(90*24*time.Hour), "s1"); err != nil {
		t.Fatalf("CheckinActive: %v", err)
	}
	if err := st1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	st2, err := Open(path)
	if err != nil {
		t.Fatalf("second Open on an already-current database: %v", err)
	}
	defer st2.Close()

	cs, err := st2.Get("spoke-a", "cert-a")
	if err != nil {
		t.Fatalf("Get after reopening: %v", err)
	}
	if cs.SerialNumber.String != "s1" {
		t.Errorf("data did not survive reopening an already-current database: got serial %q, want %q", cs.SerialNumber.String, "s1")
	}
}

// TestOpen_EnablesWALMode proves the _journal_mode=WAL DSN parameter
// Open passes to modernc.org/sqlite actually took effect, by reading the
// setting back from a real connection rather than trusting the DSN string
// alone - a typo in the parameter name would otherwise fail silently.
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

// TestOpen_SetsBusyTimeout is TestOpen_EnablesWALMode's counterpart for
// the other DSN parameter.
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

// TestOpen_ConcurrentWritesDontFailImmediately is the real-behavior proof
// that busy_timeout does what it's for: without it, one connection
// holding SQLite's write lock makes another connection's concurrent write
// fail immediately with SQLITE_BUSY ("database is locked") instead of
// waiting for the lock to free up. Deliberately uses two real goroutines
// against one real temp-file database rather than asserting anything
// about the PRAGMA value alone, since that's the actual failure mode an
// operator would see (a spoke's checkin getting a 500).
func TestOpen_ConcurrentWritesDontFailImmediately(t *testing.T) {
	st := openTestStore(t)

	const writesPerGoroutine = 25
	var wg sync.WaitGroup
	errs := make(chan error, 2*writesPerGoroutine)

	writer := func(spokeID string) {
		defer wg.Done()
		for i := 0; i < writesPerGoroutine; i++ {
			name := fmt.Sprintf("cert-%d", i)
			if err := st.CheckinActive(spokeID, name, time.Now(), time.Now().Add(24*time.Hour), "s1"); err != nil {
				errs <- err
			}
		}
	}

	wg.Add(2)
	go writer("spoke-a")
	go writer("spoke-b")
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent CheckinActive failed (want busy_timeout to make it wait, not fail): %v", err)
	}
}
