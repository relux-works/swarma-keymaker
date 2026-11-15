//go:build linux

package keymaker

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// A bounded, internally consistent read-only node model exercises the imported
// complete grant verifier, including raw txids, name outputs, W input signatures,
// issuance commitment and unspent seal. It is not a live Namecoin node or native
// qualification, and never returns a fabricated rental verdict.
type j7NodeFixture struct {
	mu           sync.Mutex
	transactions map[string]map[string]any
	blocks       map[int64][]string
	names        map[string]map[string]any
	tip          int64
	seal         su.Point
	sealOutput   su.Output
	spent        bool
	unavailable  bool
	calls        int
	utxos        int
	onUTXO       func(int)
}

func j7BlockHash(h int64) string {
	if h == 0 {
		return su.RegtestGenesis
	}
	return j7Hash([]byte(fmt.Sprintf("j7-block-%d", h)))
}
func (n *j7NodeFixture) Call(ctx context.Context, method string, args ...any) (json.RawMessage, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.calls++
	if ctx.Err() != nil || n.unavailable {
		return nil, fmt.Errorf("fixture node unavailable")
	}
	var value any
	switch method {
	case "getblockchaininfo":
		value = map[string]any{"chain": "regtest", "blocks": n.tip, "headers": n.tip, "bestblockhash": j7BlockHash(n.tip), "initialblockdownload": false}
	case "getblockhash":
		var h int64
		switch v := args[0].(type) {
		case int:
			h = int64(v)
		case int64:
			h = v
		default:
			return nil, fmt.Errorf("height type")
		}
		value = j7BlockHash(h)
	case "getblockheader":
		hash := args[0].(string)
		found := false
		for h := int64(0); h <= n.tip; h++ {
			if j7BlockHash(h) == hash {
				value = map[string]any{"hash": hash, "height": h, "confirmations": n.tip - h + 1}
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("unknown header")
		}
	case "getblock":
		hash := args[0].(string)
		found := false
		for h := int64(0); h <= n.tip; h++ {
			if j7BlockHash(h) == hash {
				value = map[string]any{"hash": hash, "height": h, "tx": n.blocks[h]}
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("unknown block")
		}
	case "getrawtransaction":
		var ok bool
		value, ok = n.transactions[args[0].(string)]
		if !ok {
			return nil, fmt.Errorf("unknown transaction")
		}
	case "name_show":
		var ok bool
		value, ok = n.names[args[0].(string)]
		if !ok {
			return nil, fmt.Errorf("unknown name")
		}
	case "getrawmempool":
		value = []string{}
	case "gettxout":
		n.utxos++
		if n.onUTXO != nil {
			n.onUTXO(n.utxos)
		}
		if args[0].(string) != n.seal.TxID || args[1].(uint32) != n.seal.Vout {
			return nil, fmt.Errorf("unexpected outpoint")
		}
		if !n.spent {
			value = map[string]any{"bestblock": j7BlockHash(n.tip), "confirmations": n.tip - 2 + 1, "value": json.Number(fmt.Sprintf("%.8f", float64(n.sealOutput.Value)/1e8)), "scriptPubKey": map[string]any{"hex": hex.EncodeToString(n.sealOutput.Script)}}
		}
	default:
		return nil, fmt.Errorf("forbidden fixture RPC %s", method)
	}
	return json.Marshal(value)
}
func (n *j7NodeFixture) add(tx *su.Transaction, raw []byte, height int64, name, value string) {
	id := tx.ID()
	vin := []any{}
	vout := []any{}
	for _, in := range tx.Inputs {
		vin = append(vin, map[string]any{"txid": in.TxID, "vout": in.Vout, "scriptSig": map[string]any{"hex": hex.EncodeToString(in.Script)}})
	}
	for i, o := range tx.Outputs {
		script := map[string]any{"hex": hex.EncodeToString(o.Script)}
		if name != "" && i == 0 {
			script["nameOp"] = map[string]any{"op": "name_update", "name": name, "value": value, "name_encoding": "ascii", "value_encoding": "ascii"}
		}
		vout = append(vout, map[string]any{"n": i, "value": json.Number(fmt.Sprintf("%.8f", float64(o.Value)/1e8)), "scriptPubKey": script})
	}
	n.transactions[id] = map[string]any{"txid": id, "hex": hex.EncodeToString(raw), "vin": vin, "vout": vout, "blockhash": j7BlockHash(height), "confirmations": n.tip - height + 1}
	n.blocks[height] = append(n.blocks[height], id)
	if name != "" {
		n.names[name] = map[string]any{"name": name, "value": value, "txid": id, "vout": 0, "height": height, "expired": false, "expires_in": 100000, "name_encoding": "ascii", "value_encoding": "ascii"}
	}
}
func j7FixturePrivate(label byte) *btcec.PrivateKey {
	var raw [32]byte
	raw[31] = label
	k, _ := btcec.PrivKeyFromBytes(raw[:])
	return k
}
func j7IssuerSignature(t *testing.T, k *btcec.PrivateKey, digest string) string {
	t.Helper()
	raw, e := hex.DecodeString(digest)
	if e != nil {
		t.Fatal(e)
	}
	sig, e := schnorr.Sign(k, raw)
	if e != nil {
		t.Fatal(e)
	}
	return hex.EncodeToString(sig.Serialize())
}
func j7WitnessFixture(t *testing.T, tx *su.Transaction, prev su.Output, key *btcec.PrivateKey) []byte {
	t.Helper()
	digest, e := su.WitnessSignatureHash(tx, 0, prev)
	if e != nil {
		t.Fatal(e)
	}
	sig := append(ecdsa.Sign(key, digest).Serialize(), 1)
	return (&su.WTransaction{Body: tx, Stacks: [][][]byte{{sig, key.PubKey().SerializeCompressed()}}}).Bytes()
}
func j7IssueFixture(t *testing.T, f *j7SignFixture, event rental.Event) (rental.SignedGrant, *j7NodeFixture, j7Evidence) {
	t.Helper()
	issuer := j7FixturePrivate(9)
	defer issuer.Zero()
	fund := j7FixturePrivate(10)
	defer fund.Zero()
	pub := hex.EncodeToString(schnorr.SerializePubKey(issuer.PubKey()))
	script, e := rental.GrantSealScript(pub)
	if e != nil {
		t.Fatal(e)
	}
	sealScript, _ := hex.DecodeString(script)
	wscript, e := su.WitnessKeyScript(fund.PubKey().SerializeCompressed())
	if e != nil {
		t.Fatal(e)
	}
	n := &j7NodeFixture{transactions: map[string]map[string]any{}, blocks: map[int64][]string{}, names: map[string]map[string]any{}, tip: 3}
	funding := &su.Transaction{Version: 1, Inputs: []su.Input{{Point: su.Point{TxID: strings.Repeat("f", 64), Vout: 0}, Sequence: 0xffffffff}}, Outputs: []su.Output{{Value: 100000, Script: wscript}, {Value: 100000, Script: wscript}}}
	signature, _ := hex.DecodeString(event.Sig)
	funding.Locktime = binary.BigEndian.Uint32(signature[:4])
	n.add(funding, funding.Bytes(), 1, "", "")
	seal := &su.Transaction{Version: 1, Inputs: []su.Input{{Point: su.Point{TxID: funding.ID(), Vout: 0}, Sequence: 0xffffffff}}, Outputs: []su.Output{{Value: 50000, Script: sealScript}}}
	n.add(seal, j7WitnessFixture(t, seal, funding.Outputs[0], fund), 2, "", "")
	n.seal = su.Point{TxID: seal.ID(), Vout: 0}
	n.sealOutput = seal.Outputs[0]
	g := rental.Grant{Version: 3, Network: "regtest", Genesis: su.RegtestGenesis, AgentName: f.contract.Agent, LandlordName: f.contract.Landlord, IssuerKey: pub, GranteeKey: f.public, ContractSHA256: j7Hash(f.raw), Scope: f.contract.scope(), NotBefore: f.contract.NotBefore, NotAfter: f.contract.NotAfter, Seal: rental.Point{TxID: seal.ID(), Vout: 0}, Consent: rental.GrantConsent{ContractSHA256: j7Hash(f.raw), ConsentEvent: event, LandlordSig: j7IssuerSignature(t, issuer, j7Hash(f.raw))}}
	if f.contract.Budget > 0 {
		v := f.contract.Budget
		g.Budget = &v
	}
	digest, e := g.SigningHash()
	if e != nil {
		t.Fatal("external grant validation", e)
	}
	signed := rental.SignedGrant{Grant: g, Signature: j7IssuerSignature(t, issuer, digest)}
	commit, e := rental.IssuanceCommitment(signed)
	if e != nil {
		t.Fatal(e)
	}
	hash, _ := hex.DecodeString(commit)
	op := append([]byte{0x6a, 0x20}, hash...)
	issuance := &su.Transaction{Version: 1, Inputs: []su.Input{{Point: su.Point{TxID: funding.ID(), Vout: 1}, Sequence: 0xffffffff}}, Outputs: []su.Output{{Value: 0, Script: op}, {Value: 90000, Script: wscript}}}
	n.add(issuance, j7WitnessFixture(t, issuance, funding.Outputs[1], fund), 3, "", "")
	agentValue, e := rental.AgentBindingValue(rental.AgentBinding{Nostr: f.public, Landlord: f.contract.Landlord})
	if e != nil {
		t.Fatal(e)
	}
	ownerValue, e := rental.LandlordValue(rental.LandlordBinding{Grant: pub})
	if e != nil {
		t.Fatal(e)
	}
	for i, v := range []struct{ name, value string }{{f.contract.Agent, agentValue}, {f.contract.Landlord, ownerValue}} {
		tx := &su.Transaction{Version: 0x7100, Inputs: []su.Input{{Point: su.Point{TxID: strings.Repeat(fmt.Sprint(i+1), 64), Vout: 0}, Sequence: 0xffffffff}}, Outputs: []su.Output{{Value: 1000000, Script: su.NameUpdateScript(v.name, v.value, []byte{0x51})}}}
		n.add(tx, tx.Bytes(), 1, v.name, v.value)
	}
	// testing.TempDir's numbered child is masked by the caller's umask. The
	// verifier requires its own exact private root, independent of that umask.
	state := filepath.Join(t.TempDir(), "rental-state")
	if e := os.Mkdir(state, 0700); e != nil {
		t.Fatal(e)
	}
	if old := f.a.evidence; old != nil {
		if prior, ok := old.policies[f.contract.Agent]; ok {
			state = prior.StateDir
		}
	}
	p := rental.Policy{ConstructionProfile: "W", Network: "regtest", Genesis: su.RegtestGenesis, AgentName: f.contract.Agent, LandlordName: f.contract.Landlord, IssuerPubkey: pub, SealScript: script, StateDir: state}
	f.f.store.mu.Lock()
	f.a.evidence = &j7RentalAuthority{node: n, policies: map[string]rental.Policy{f.contract.Agent: p}}
	f.f.store.mu.Unlock()
	evidence := j7Evidence{Format: "keymaker-j7-evidence/1", Issuance: issuance.ID()}
	return signed, n, evidence
}

// The real verifier accepts the complete fixture with its private state root,
// then refuses an unsafe mode before RPC or state-file changes. This is an
// offline node model, not live chain or custody qualification.
func TestJ7NodeFixturePrivateState(t *testing.T) {
	f := j7SigningSetup(t)
	c := f.dial(t, 1)
	f.bind(t, c, 2, f.f.origin, f.f.uid+200)
	event := j7ResultEvent(t, j7Call(t, c, 3, "j7_sign", f.consent(t), ""))
	grant, node, evidence := j7IssueFixture(t, f, event)
	policy := f.a.evidence.policies[grant.Grant.AgentName]
	raw, err := json.Marshal(rental.GrantPresentation{SignedGrant: grant, Issuance: rental.IssuanceProof{TxID: evidence.Issuance}})
	if err != nil {
		t.Fatal(err)
	}
	at, _ := (fixtureAuditClock{}).UTC()
	check := func() rental.Receipt {
		return rental.Check(t.Context(), node, policy, raw, grant.Grant.AgentName, grant.Grant.GranteeKey, at.Unix())
	}
	if info, err := os.Stat(policy.StateDir); err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("fixture state root is not private", err)
	}
	if receipt := check(); receipt.Verdict != "live" || receipt.Reason != "LIVE" || receipt.GrantID != grant.ID() || receipt.Closed {
		t.Fatalf("complete fixture refused: %+v", receipt)
	}
	snapshot := func() map[string]string {
		files := map[string]string{}
		entries, err := os.ReadDir(policy.StateDir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			raw, err := os.ReadFile(filepath.Join(policy.StateDir, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			files[entry.Name()] = string(raw)
		}
		return files
	}
	before := snapshot()
	node.mu.Lock()
	calls := node.calls
	node.mu.Unlock()
	if err := os.Chmod(policy.StateDir, 0755); err != nil {
		t.Fatal(err)
	}
	if receipt := check(); receipt.Verdict != "refused" || receipt.Reason != "PRIVATE_STATE_ROOT" {
		t.Fatalf("unsafe state root did not refuse: %+v", receipt)
	}
	node.mu.Lock()
	unchangedCalls := node.calls == calls
	node.mu.Unlock()
	if !unchangedCalls || !reflect.DeepEqual(before, snapshot()) {
		t.Fatal("unsafe-root refusal reached RPC or changed verifier state files")
	}
}
