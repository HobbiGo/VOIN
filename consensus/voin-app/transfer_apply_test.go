package voinapp

import "testing"

func TestSignedTransferAndReplay(t *testing.T) {
	state, envelope, sk := testTransferFixture(t)
	raw := signTestTransfer(t, envelope, sk)
	before, err := state.Hash()
	if err != nil {
		t.Fatal(err)
	}
	next, err := ApplySignedTransfer(state, raw)
	if err != nil {
		t.Fatal(err)
	}
	sender := envelope.Transfer.Sender
	recipient := envelope.Transfer.Recipient
	if next.Accounts[sender].Balance != 750 ||
		next.Accounts[sender].Nonce != 1 ||
		next.Accounts[recipient].Balance != 250 {
		t.Fatal("incorrect transfer balances or nonce")
	}
	after, err := state.Hash()
	if err != nil || after != before {
		t.Fatal("transfer modified original state")
	}
	committed, err := next.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplySignedTransfer(next, raw); err == nil {
		t.Fatal("replayed transaction accepted")
	}
	unchanged, err := next.Hash()
	if err != nil || unchanged != committed {
		t.Fatal("replay rejection modified state")
	}
}

func TestInvalidTransfersPreserveState(t *testing.T) {
	cases := []struct {
		name string
		edit func(*State, *SignedTransfer)
	}{
		{"insufficient balance", func(s *State, e *SignedTransfer) {
			e.Transfer.Amount = 1001
		}},
		{"wrong network", func(s *State, e *SignedTransfer) {
			e.Transfer.ChainID = "other-network"
		}},
		{"wrong nonce", func(s *State, e *SignedTransfer) {
			e.Transfer.Nonce = 2
		}},
		{"zero amount", func(s *State, e *SignedTransfer) {
			e.Transfer.Amount = 0
		}},
		{"overflow", func(s *State, e *SignedTransfer) {
			s.Accounts[e.Transfer.Recipient] = Account{
				Balance: ^uint64(0),
			}
		}},
		{"exhausted nonce", func(s *State, e *SignedTransfer) {
			account := s.Accounts[e.Transfer.Sender]
			account.Nonce = ^uint64(0)
			s.Accounts[e.Transfer.Sender] = account
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			state, envelope, sk := testTransferFixture(t)
			test.edit(state, &envelope)
			raw := signTestTransfer(t, envelope, sk)
			before, err := state.Hash()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ApplySignedTransfer(state, raw); err == nil {
				t.Fatal("invalid transfer accepted")
			}
			after, err := state.Hash()
			if err != nil || after != before {
				t.Fatal("rejection changed original state")
			}
		})
	}
}
