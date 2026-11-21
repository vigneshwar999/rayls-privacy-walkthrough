// rayls-privacy-walkthrough
//
// Follows one payment through Rayls' private-network cryptography, using the
// functions from Rayls' open-source code, copied with the standard-library
// equivalents of their imports (crypto/mlkem, crypto/sha3, crypto/hkdf, AES-GCM).
//
// Sources (pinned):
//   relayer    github.com/raylsnetwork/rayls-sovereign-relayer       @ b01b427
//     cryptography/encrypt.go       HashIt, EncryptGCM, DecryptGCM, DeriveSymmetricKey, KMAC
//     cts/keygen/rayls_view_keys.go GenerateRaylsViewKeys, GenerateSharedSecret
//     cts/service/encrypt.go        GCMEncryptWithNormalMessageTag, generateNormalMessageTag, EncryptPrivateKey
//   governance github.com/raylsnetwork/rayls-sovereign-pnh-governance @ 2f2bf83
//     cryptography/service.go                      DecryptAuditPrivateKey
//     cmd/listener/adapters/crypto/decryptor.go    processAuditEntry, processPairSecret
//
// No network, no live chain, no private data: every key is generated fresh on this run.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"math/big"
	"os"
	"strings"
)

// ---- relayer: cryptography/encrypt.go -------------------------------------

func HashIt(data []byte) []byte {
	h := sha3.New256()
	h.Write(data)
	return h.Sum(nil)
}

func EncryptGCM(key, plaintext, associatedData []byte) ([]byte, error) {
	if len(key) < 32 {
		key = HashIt(key)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, associatedData)
	out := append([]byte{}, associatedData...)
	out = append(out, nonce...)
	return append(out, ct...), nil
}

func DecryptGCM(ciphertext, key []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	ad := ciphertext[0:16]
	nonce := ciphertext[16 : 16+gcm.NonceSize()]
	pt, err := gcm.Open(nil, nonce, ciphertext[16+gcm.NonceSize():], ad)
	return ad, pt, err
}

func DeriveSymmetricKey(sharedSecret []byte) ([]byte, error) {
	// relayer: hkdf.New(sha3.New256, sharedSecret, nil, []byte("Rayls")), read 32 bytes
	return hkdf.Key(func() hash.Hash { return sha3.New256() }, sharedSecret, nil, "Rayls", 32)
}

func KMAC(key, data []byte) []byte {
	h := sha3.New256()
	h.Write(key)
	h.Write(data)
	return h.Sum(nil)
}

// ---- relayer: cts/keygen/rayls_view_keys.go -------------------------------

func GenerateRaylsViewKeys() (*mlkem.DecapsulationKey768, *mlkem.EncapsulationKey768) {
	dk, err := mlkem.GenerateKey768()
	must(err)
	return dk, dk.EncapsulationKey()
}

func GenerateSharedSecret(encapsulationKey []byte) (ciphertext, sharedSecret []byte) {
	ek, err := mlkem.NewEncapsulationKey768(encapsulationKey)
	must(err)
	sharedSecret, ciphertext = ek.Encapsulate()
	return
}

// ---- relayer: cts/service/encrypt.go ---------------------------------------

func generateNormalMessageTag(prevBlockHash string, sharedSecret []byte, chainID *big.Int) []byte {
	var data string
	if len(prevBlockHash) != 0 {
		data = prevBlockHash[2:] + chainID.String() + hex.EncodeToString(sharedSecret)
	} else {
		data = prevBlockHash + chainID.String() + hex.EncodeToString(sharedSecret)
	}
	return HashIt([]byte(data))[0:16]
}

func GCMEncryptWithNormalMessageTag(blob, sharedSecret []byte, receiverChainID *big.Int, prevBlockHash string) ([]byte, []byte) {
	tag := generateNormalMessageTag(prevBlockHash, sharedSecret, receiverChainID)
	key, err := DeriveSymmetricKey(sharedSecret)
	must(err)
	enc, err := EncryptGCM(key, blob, tag)
	must(err)
	return enc, tag
}

// EncryptPrivateKey: the bank encrypts its View private key under the secret it shares with the operator.
func EncryptPrivateKey(viewDK *mlkem.DecapsulationKey768, operatorSharedSecret []byte) (encrypted, mac []byte) {
	key, err := DeriveSymmetricKey(operatorSharedSecret)
	must(err)
	pkJSON, err := json.Marshal(viewDK.Bytes())
	must(err)
	encrypted, err = EncryptGCM(key, pkJSON, make([]byte, 16))
	must(err)
	return encrypted, KMAC(operatorSharedSecret, encrypted)
}

// ---- governance: cryptography/service.go -----------------------------------

func DecryptAuditPrivateKey(encrypted, mac, sharedSecret []byte) ([]byte, error) {
	if !bytes.Equal(mac, KMAC(sharedSecret, encrypted)) {
		return nil, fmt.Errorf("MAC verification failed")
	}
	key, err := DeriveSymmetricKey(sharedSecret)
	if err != nil {
		return nil, err
	}
	_, pt, err := DecryptGCM(encrypted, key)
	if err != nil {
		return nil, err
	}
	var raw []byte
	return raw, json.Unmarshal(pt, &raw)
}

// ---- the walkthrough --------------------------------------------------------

type step struct {
	N      int               `json:"n"`
	Layer  string            `json:"layer"`
	Who    string            `json:"who"`
	What   string            `json:"what"`
	Values map[string]string `json:"values"`
	Result string            `json:"result"`
}

var steps []step

func record(layer, who, what, result string, kv ...string) {
	v := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		v[kv[i]] = kv[i+1]
	}
	steps = append(steps, step{len(steps) + 1, layer, who, what, v, result})
	fmt.Printf("\n[%02d] %-9s %-12s %s\n", len(steps), layer, who, what)
	for i := 0; i+1 < len(kv); i += 2 {
		fmt.Printf("       %-22s %s\n", kv[i], kv[i+1])
	}
	fmt.Printf("       => %s\n", result)
}

func short(b []byte) string {
	h := hex.EncodeToString(b)
	if len(h) > 20 {
		return h[:12] + "…" + h[len(h)-8:]
	}
	return h
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	bankA, bankB, bankC, operator := big.NewInt(101), big.NewInt(102), big.NewInt(103), big.NewInt(1)

	// Layer 2 setup: View keys
	dkA, ekA := GenerateRaylsViewKeys()
	dkB, ekB := GenerateRaylsViewKeys()
	dkC, _ := GenerateRaylsViewKeys()
	dkOp, ekOp := GenerateRaylsViewKeys()
	record("setup", "all", "Each party generates an ML-KEM-768 View key pair", "4 key pairs",
		"public key size", fmt.Sprintf("%d bytes", len(ekA.Bytes())),
		"private key size", fmt.Sprintf("%d bytes (seed)", len(dkA.Bytes())))

	// One-time key agreement A -> B (A encapsulates to B's public key; ciphertext goes on the Hub)
	ctAB, ssAB := GenerateSharedSecret(ekB.Bytes())
	ssAB_atB, err := dkB.Decapsulate(ctAB)
	must(err)
	record("layer 2", "Bank A ↔ B", "One-time ML-KEM key agreement; only the ciphertext is public", "both banks hold the same 32-byte secret: "+fmt.Sprint(bytes.Equal(ssAB, ssAB_atB)),
		"ciphertext on Hub", fmt.Sprintf("%s (%d bytes)", short(ctAB), len(ctAB)),
		"shared secret", short(ssAB))

	// Layer 2: the payment message
	payment := []byte(`{"from":"BankA:0xA11CE","to":"BankB:0xB0B","asset":"tokenized BRL deposit","amount":"250000.00"}`)
	prevHash := "0x" + hex.EncodeToString(HashIt([]byte("block 41")))
	enc, tag := GCMEncryptWithNormalMessageTag(payment, ssAB, bankB, prevHash)
	record("layer 2", "Bank A", "Encrypts a payment to Bank B (AES-256-GCM, key = HKDF-SHA3(secret, \"Rayls\"))", "what the Hub stores: tag + ciphertext only",
		"plaintext", string(payment),
		"message tag", hex.EncodeToString(tag),
		"stored on Hub", fmt.Sprintf("%s (%d bytes)", short(enc), len(enc)))

	// Bank B finds and reads it
	tryTag := generateNormalMessageTag(prevHash, ssAB_atB, bankB)
	keyB, _ := DeriveSymmetricKey(ssAB_atB)
	_, ptB, errB := DecryptGCM(enc, keyB)
	record("layer 2", "Bank B", "Recomputes the tag with its secret, matches it, decrypts", "reads: "+string(ptB),
		"tag match", fmt.Sprint(bytes.Equal(tryTag, tag)),
		"decrypt error", fmt.Sprint(errB))

	// Bank C (not involved) tries
	ctAC, ssAC := GenerateSharedSecret(dkC.EncapsulationKey().Bytes())
	_ = ctAC
	tagC := generateNormalMessageTag(prevHash, ssAC, bankC)
	keyC, _ := DeriveSymmetricKey(ssAC)
	_, _, errC := DecryptGCM(enc, keyC)
	record("layer 2", "Bank C", "A bank not in the payment tries with its own secret", "cannot read it",
		"tag match", fmt.Sprint(bytes.Equal(tagC, tag)),
		"decrypt", strings.TrimPrefix(fmt.Sprint(errC), "cipher: "))

	// Tag changes every block
	prev2 := "0x" + hex.EncodeToString(HashIt([]byte("block 42")))
	_, tag2 := GCMEncryptWithNormalMessageTag(payment, ssAB, bankB, prev2)
	record("layer 2", "observer", "Same banks, same payment, next block", "tags don't repeat, so an outsider can't link messages",
		"tag at block 42", hex.EncodeToString(tag),
		"tag at block 43", hex.EncodeToString(tag2))

	// Layer 4: audit escrow. Each bank agrees a secret with the operator and escrows its View private key.
	escrow := func(name string, dk *mlkem.DecapsulationKey768) (ct, encKey, mac []byte) {
		ct, ss := GenerateSharedSecret(ekOp.Bytes())
		encKey, mac = EncryptPrivateKey(dk, ss)
		return
	}
	ctAop, encA, macA := escrow("A", dkA)
	ctBop, encB, macB := escrow("B", dkB)
	record("layer 4", "Banks A, B", "Each bank encrypts its View private key to the operator (AuditInfo)", "stored on the Hub, readable only with the operator's key",
		"Bank A AuditInfo", fmt.Sprintf("%s (%d bytes)", short(encA), len(encA)),
		"Bank A MAC (SHA3)", short(macA),
		"Bank B AuditInfo", fmt.Sprintf("%s (%d bytes)", short(encB), len(encB)))

	// Governance: processAuditEntry for each bank
	recover := func(ct, enc, mac []byte) *mlkem.DecapsulationKey768 {
		ss, err := dkOp.Decapsulate(ct)
		must(err)
		raw, err := DecryptAuditPrivateKey(enc, mac, ss)
		must(err)
		dk, err := mlkem.NewDecapsulationKey768(raw)
		must(err)
		return dk
	}
	recA := recover(ctAop, encA, macA)
	recB := recover(ctBop, encB, macB)
	record("layer 4", "Operator", "processAuditEntry: opens each AuditInfo with the operator key", "recovered keys match the banks' own",
		"Bank A key matches", fmt.Sprint(bytes.Equal(recA.Bytes(), dkA.Bytes())),
		"Bank B key matches", fmt.Sprint(bytes.Equal(recB.Bytes(), dkB.Bytes())))

	// Governance: processPairSecret — decapsulate A->B agreement with B's recovered key
	ssOp, err := recB.Decapsulate(ctAB)
	must(err)
	keyOp, _ := DeriveSymmetricKey(ssOp)
	_, ptOp, errOp := DecryptGCM(enc, keyOp)
	record("layer 4", "Operator", "processPairSecret: rebuilds the A↔B secret, decrypts the payment for audit", "reads: "+string(ptOp),
		"pair secret matches", fmt.Sprint(bytes.Equal(ssOp, ssAB)),
		"decrypt error", fmt.Sprint(errOp))

	// Key rotation: A rotates; same escrow step runs; operator still sees
	dkA2, _ := GenerateRaylsViewKeys()
	ct2, enc2, mac2 := escrow("A", dkA2)
	recA2 := recover(ct2, enc2, mac2)
	record("layer 4", "Bank A", "Rotates its View key; UpdateRaylsViewKeys escrows the new one too", "audit view continues after rotation",
		"new key differs", fmt.Sprint(!bytes.Equal(dkA2.Bytes(), dkA.Bytes())),
		"operator recovers new key", fmt.Sprint(bytes.Equal(recA2.Bytes(), dkA2.Bytes())))

	_ = operator
	_ = bankA
	out, _ := json.MarshalIndent(steps, "", "  ")
	must(os.WriteFile("walkthrough.json", out, 0o644))
	fmt.Println("\nwrote walkthrough.json")
}
