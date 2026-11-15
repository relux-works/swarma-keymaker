package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

type signingContract struct {
	Profile   string   `json:"profile"`
	Network   string   `json:"network"`
	Landlord  string   `json:"landlord_name"`
	Agent     string   `json:"agent_name"`
	Grantee   string   `json:"grantee_key"`
	Actions   []string `json:"actions"`
	Repos     []string `json:"repos"`
	Budget    int64    `json:"spend_budget"`
	NotBefore int64    `json:"not_before"`
	NotAfter  int64    `json:"not_after"`
	Note      string   `json:"note"`
}
type signingCase struct {
	ID       string `json:"id"`
	Event    string `json:"event_b64"`
	Expected string `json:"expected"`
}
type signingVectors struct {
	Format      string        `json:"format"`
	TestOnly    bool          `json:"test_only"`
	Note        string        `json:"note"`
	Source      string        `json:"source"`
	Contract    string        `json:"contract_b64"`
	Grant       string        `json:"grant_b64"`
	Instruction string        `json:"instruction_b64"`
	Positive    []signingCase `json:"positive"`
	Negative    []signingCase `json:"negative"`
}

// Entirely synthetic published scalars/nonces. This independent fixture builder
// never imports the product signer or opens custody, journals, sockets or RPC.
func signingFixture() signingVectors {
	private := make([]byte, 32)
	private[31] = 3
	key, _ := btcec.PrivKeyFromBytes(private)
	defer key.Zero()
	private[31] = 9
	issuer, _ := btcec.PrivKeyFromBytes(private)
	defer issuer.Zero()
	clear(private)
	pub := hex.EncodeToString(schnorr.SerializePubKey(key.PubKey()))
	issuerPub := hex.EncodeToString(schnorr.SerializePubKey(issuer.PubKey()))
	sign := func(key *btcec.PrivateKey, hash string) string {
		var aux [32]byte
		sig, e := schnorr.Sign(key, decodeHex(hash), schnorr.CustomNonce(aux))
		fail(e)
		return hex.EncodeToString(sig.Serialize())
	}
	event := func(e rental.Event) rental.Event {
		e.ID = authorityHash(authorityBytes([]any{0, e.Pubkey, e.CreatedAt, e.Kind, e.Tags, e.Content}))
		e.Sig = sign(key, e.ID)
		return e
	}
	c := signingContract{"swarma-trust-contract/1", "regtest", "id/example-owner", "id/example-executor", pub, []string{"instruct", "land", "review", "spend"}, []string{"https://example.test/team/repository"}, 100, 1700000000, 1700003600, "Public synthetic fixture"}
	contract := authorityBytes(c)
	hash := authorityHash(contract)
	consent := event(rental.Event{Pubkey: pub, CreatedAt: 1700000001, Kind: 8181, Tags: [][]string{{"t", "swarma-rental-consent-v1"}, {"contract", hash}, {"booking", authorityHash(append(append([]byte{}, contract...), []byte("booking")...))}, {"privacy", authorityHash([]byte("swarma-trust-privacy-v1"))}}, Content: ""})
	budget := int64(100)
	g := rental.Grant{Version: 3, Network: "regtest", Genesis: su.RegtestGenesis, AgentName: c.Agent, LandlordName: c.Landlord, IssuerKey: issuerPub, GranteeKey: pub, ContractSHA256: hash, Scope: []string{"pay", "repository.push"}, Budget: &budget, NotBefore: c.NotBefore, NotAfter: c.NotAfter, Seal: rental.Point{TxID: strings.Repeat("a", 64), Vout: 0}, Consent: rental.GrantConsent{ContractSHA256: hash, ConsentEvent: consent, LandlordSig: sign(issuer, hash)}}
	digest, e := g.SigningHash()
	fail(e)
	grant := rental.SignedGrant{Grant: g, Signature: sign(issuer, digest)}
	grantRaw, e := json.Marshal(grant)
	fail(e)
	enc := base64.RawURLEncoding.EncodeToString
	f := signingVectors{Format: "keymaker-j7-signing-vectors/1", TestOnly: true, Note: "Draft profile/1 byte/signature controls only. Synthetic signed grant has no issuance/live proof; no RPC, custody, native qualification or external kind8185 interoperability. Profile/2 and kind8186 unsupported.", Source: "LIP-0013 sections 2.4 and 3; rental e70a35a41dec5948d5452f1f898f4d26977372d7; trustcheck 45054797ee9ad3e38213e067051dfbd3eb2a21a1", Contract: enc(contract), Grant: enc(grantRaw), Instruction: enc([]byte("Review the public fixture.")), Positive: []signingCase{{"consent", enc(authorityBytes(consent)), "valid"}}, Negative: []signingCase{}}
	var land, spend rental.Event
	for _, action := range c.Actions {
		tags := [][]string{{"t", "swarma-instruction-v1"}, {"to", c.Agent}, {"grant", grant.ID()}, {"action", action}, {"body", authorityHash([]byte("Review the public fixture."))}, {"room", "!example:example.test"}, {"mxid", "@example:example.test"}, {"nonce", strings.Repeat("1", 64)}}
		if action == "land" {
			tags = append(tags, []string{"repo", c.Repos[0]})
		}
		if action == "spend" {
			tags = append(tags, []string{"amount", "100"})
		}
		v := event(rental.Event{Pubkey: pub, CreatedAt: 1700000002, Kind: 8185, Tags: tags, Content: ""})
		f.Positive = append(f.Positive, signingCase{action, enc(authorityBytes(v)), "valid"})
		if action == "land" {
			land = v
		}
		if action == "spend" {
			spend = v
		}
	}
	add := func(id string, v rental.Event) {
		v = event(v)
		f.Negative = append(f.Negative, signingCase{id, enc(authorityBytes(v)), "invalid"})
	}
	v := consent
	v.Kind = 8186
	add("unavailable-kind8186", v)
	v = consent
	v.Content = "forwarded content"
	add("nonempty-content", v)
	v = land
	v.Tags = append([][]string{}, land.Tags...)
	v.Tags[1], v.Tags[2] = v.Tags[2], v.Tags[1]
	add("reordered-tags", v)
	v = land
	v.Tags = append(append([][]string{}, land.Tags...), []string{"extra", "selector"})
	add("extra-tag", v)
	v = spend
	v.Tags = append([][]string{}, spend.Tags...)
	v.Tags[8] = []string{"amount", "0100"}
	add("noncanonical-amount", v)
	v = land
	v.ID = strings.Repeat("0", 64)
	f.Negative = append(f.Negative, signingCase{"altered-id", enc(authorityBytes(v)), "invalid"})
	v = land
	v.Sig = strings.Repeat("0", 128)
	f.Negative = append(f.Negative, signingCase{"altered-signature", enc(authorityBytes(v)), "invalid"})
	f.Negative = append(f.Negative, signingCase{"noncanonical-event", enc(append(authorityBytes(land), '\n')), "invalid"})
	return f
}
func signingVectorBytes() []byte {
	raw, e := json.MarshalIndent(signingFixture(), "", "  ")
	fail(e)
	return append(raw, '\n')
}
func checkJ7SigningVectors() {
	raw, e := os.ReadFile("vectors/j7/signing.json")
	fail(e)
	require(bytes.Equal(raw, signingVectorBytes()), "J7 signing fixture bytes drift")
	fmt.Println("J7 signing fixtures: exact 5 positive and 8 negative draft profile/1 byte/signature controls; live authority NOT qualified")
}
