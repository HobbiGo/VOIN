package voinapp

import (
	"errors"
	"os"
	"path/filepath"
)

// NewFreshPersistentApp is for a new, single-process local experiment.
// It does not provide a multi-process file lock.
func NewFreshPersistentApp(path string) (*App, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("absolute state file path required")
	}
	if _, err := os.Lstat(path); err == nil {
		return nil, errors.New("state already exists; use checkpoint recovery")
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	if !parent.IsDir() {
		return nil, errors.New("state parent is not a directory")
	}
	return &App{stateFile: path}, nil
}
