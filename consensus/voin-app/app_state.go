package voinapp

import "errors"

// NewAppWithAllocations creates an in-memory application for testing.
// It does not implement ABCI genesis initialization or persistence.
func NewAppWithAllocations(allocations map[string]uint64) (*App, error) {
	state, err := NewState(allocations)
	if err != nil {
		return nil, err
	}
	return &App{state: state}, nil
}

func (app *App) StateHash() ([32]byte, error) {
	if app == nil || app.state == nil {
		return [32]byte{}, errors.New("application state not initialized")
	}
	return app.state.Hash()
}
