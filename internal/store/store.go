// Package store keeps cases and the audit log on disk. Everything is private
// to the user: folders are 0700 and files 0600.
package store

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Case is one piece of work: what is being tested, what may be tested, and
// the analyst's notes.
type Case struct {
	Name    string    `json:"name"`
	Created time.Time `json:"created"`
	Targets []string  `json:"targets"`
	Active  string    `json:"active,omitempty"` // the target tools start with
	Scope   []string  `json:"scope"`
	Notes   string    `json:"notes"`
}

// Entry is one line of the audit log: one command Cairn ran.
type Entry struct {
	Time     time.Time `json:"time"`
	Tool     string    `json:"tool"`
	Argv     []string  `json:"argv"`
	Target   string    `json:"target,omitempty"`
	Scope    string    `json:"scope"`
	Override bool      `json:"override,omitempty"`
	Exit     int       `json:"exit"`
	Seconds  float64   `json:"seconds"`
	Findings int       `json:"findings"`
	Error    string    `json:"error,omitempty"`
}

// Store is a folder of cases.
type Store struct {
	dir string
	mu  sync.Mutex
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,39}$`)

// ErrName is returned for a case name that is not a short word of letters,
// digits, dashes and underscores.
var ErrName = errors.New("a case name is 1 to 40 letters, digits, - or _, starting with a letter or digit")

// CleanName lowercases and checks a case name.
func CleanName(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if !nameRE.MatchString(s) {
		return "", ErrName
	}
	return s, nil
}

// Dir is where Cairn keeps its files: $CAIRN_HOME, else the XDG data
// directory.
func Dir() string {
	if d := os.Getenv("CAIRN_HOME"); d != "" {
		return d
	}
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return filepath.Join(d, "cairn")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".local", "share", "cairn")
}

// Open returns the store at dir (Dir() when empty), creating it.
func Open(dir string) (*Store, error) {
	if dir == "" {
		dir = Dir()
	}
	if err := os.MkdirAll(filepath.Join(dir, "cases"), 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

// Path is where a case's files start.
func (s *Store) Path(name string) string { return filepath.Join(s.dir, "cases", name) }

func (s *Store) caseFile(name string) string { return s.Path(name) + ".json" }
func (s *Store) logFile(name string) string  { return s.Path(name) + ".log.jsonl" }

// Dir is the folder holding the cases.
func (s *Store) Dir() string { return filepath.Join(s.dir, "cases") }

// List names the cases, oldest name first.
func (s *Store) List() []string {
	ents, _ := os.ReadDir(filepath.Join(s.dir, "cases"))
	var names []string
	for _, e := range ents {
		if n, ok := strings.CutSuffix(e.Name(), ".json"); ok && nameRE.MatchString(n) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names
}

// Load reads a case.
func (s *Store) Load(name string) (*Case, error) {
	name, err := CleanName(name)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(s.caseFile(name))
	if err != nil {
		return nil, err
	}
	var c Case
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("case %s is damaged: %w", name, err)
	}
	c.Name = name
	return &c, nil
}

// Save writes a case. A crash part-way leaves the old file intact.
func (s *Store) Save(c *Case) error {
	name, err := CleanName(c.Name)
	if err != nil {
		return err
	}
	c.Name = name
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tmp, err := os.CreateTemp(filepath.Join(s.dir, "cases"), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.caseFile(name))
}

// Create makes a new, empty case. It refuses a name already in use.
func (s *Store) Create(name string) (*Case, error) {
	name, err := CleanName(name)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(s.caseFile(name)); err == nil {
		return nil, fmt.Errorf("there is already a case called %s", name)
	}
	c := &Case{Name: name, Created: time.Now().UTC().Truncate(time.Second)}
	return c, s.Save(c)
}

// Current is the name of the case in use, or "" if none has been chosen.
func (s *Store) Current() string {
	b, err := os.ReadFile(filepath.Join(s.dir, "current"))
	if err != nil {
		return ""
	}
	n := strings.TrimSpace(string(b))
	if _, err := os.Stat(s.caseFile(n)); err != nil || !nameRE.MatchString(n) {
		return ""
	}
	return n
}

// SetCurrent makes name the case in use.
func (s *Store) SetCurrent(name string) error {
	name, err := CleanName(name)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.dir, "current"), []byte(name+"\n"), 0o600)
}

// Append adds an entry to a case's audit log.
func (s *Store) Append(name string, e Entry) error {
	name, err := CleanName(name)
	if err != nil {
		return err
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.logFile(name), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Entries reads a case's audit log, oldest first. A line that cannot be
// read is skipped; one bad line must not hide the rest of the record.
func (s *Store) Entries(name string) ([]Entry, error) {
	name, err := CleanName(name)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(s.logFile(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		var e Entry
		if json.Unmarshal(sc.Bytes(), &e) == nil && !e.Time.IsZero() {
			out = append(out, e)
		}
	}
	return out, sc.Err()
}
