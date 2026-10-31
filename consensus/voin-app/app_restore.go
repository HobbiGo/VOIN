package voinapp

import "errors"

// NewAppFromCheckpoint restores a local application.
// The caller must obtain trustedHash independently of the state file.
func NewAppFromCheckpoint(
	path string,
	trustedHash [32]byte,
) (*App, error) {
	if path == "" {
		return nil, errors.New("state file path required")
	}
	state, err := readStateFile(path, trustedHash)
	if err != nil {
		return nil, err
	}
	return &App{
		state:     state,
		stateFile: path,
	}, nil
}
