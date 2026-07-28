// One-off generator: dump deterministic ltcd MWEB PSBT / output fixtures for bdk_mweb.
//
// Regenerates files under ../../crates/mweb/tests/fixtures/.
// Requires CGO (secp256k1 range proofs). See README.md.
// Not used by Rust CI.
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"encoding/binary"

	"github.com/ltcsuite/ltcd/chaincfg/chainhash"
	"github.com/ltcsuite/ltcd/ltcutil"
	"github.com/ltcsuite/ltcd/ltcutil/mweb"
	"github.com/ltcsuite/ltcd/ltcutil/mweb/mw"
	"github.com/ltcsuite/ltcd/ltcutil/psbt"
	"github.com/ltcsuite/ltcd/wire"
	"github.com/ltcsuite/secp256k1"
	"lukechampine.com/blake3"
)

// Fixed seeds — documented in README.md and mirrored by Rust tests.
var (
	scanSecret  = mustHex32("b3c91b7291c2e1e06d4a93f3dc32404aef9927db8e794c01a7b4de18a397c338")
	spendSecret = mustHex32("2fe1982b98c0b68c0839421c8a0a0a67ef3198c746ab8e6d09101eb7396a44d8")

	psbtInputSender = mustHex32("1111111111111111111111111111111111111111111111111111111111111111")
	psbtOutputId    = mustHex32("2222222222222222222222222222222222222222222222222222222222222222")
	psbtOutputScan  = mustHex32("3333333333333333333333333333333333333333333333333333333333333333")
	psbtOutputSpend = mustHex32("4444444444444444444444444444444444444444444444444444444444444444")

	wrongKeySender = mustHex32("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	kernelAllFieldsHex = "010021093d957d9c2a301532ffc9c11344e87ad252eccbac597bac6567ba38a2365bea14010121022a969b0465d5e8a24fc0659710925b534e82e81f7677a3012bb8d550dcff9f1c0102081027000000000000010308204e0000000000000204000fa0860100000000000676a9142088ac0204010f80841e00000000000676a9142088ac010504960000000106013f01070a65787472612064617461010840e12804f0a96165fbabeda93782cc0b79e92faab448d72e728dfba7fa82771f0f8195c80e5b8754f01cdf53fca8fe9820b15074d4ae5cfb01b5307c64c51f62cf03fc00010b70726f707269657461727900"
)

func mustHex32(s string) [32]byte {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		panic(s)
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

func sk(b [32]byte) *mw.SecretKey { return (*mw.SecretKey)(&b) }

func keychain() *mweb.Keychain {
	return &mweb.Keychain{Scan: sk(scanSecret), Spend: sk(spendSecret)}
}

func main() {
	outDir := filepath.Join("..", "..", "crates", "mweb", "tests", "fixtures")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fatal(err)
	}
	if err := writeOutputs(outDir); err != nil {
		fatal(err)
	}
	if err := writeWrongScanOutput(outDir); err != nil {
		fatal(err)
	}
	if err := writeFile(outDir, "kernel_all_fields.hex", []byte(kernelAllFieldsHex+"\n")); err != nil {
		fatal(err)
	}
	if err := writeSignMwebPsbt(outDir); err != nil {
		fatal(err)
	}
	if err := writeExtractValid(outDir); err != nil {
		fatal(err)
	}
	fmt.Println("wrote fixtures to", outDir)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}

func writeFile(dir, name string, data []byte) error {
	return os.WriteFile(filepath.Join(dir, name), data, 0o644)
}

func multiIndexSender(i int) [32]byte {
	var sender [32]byte
	sender[0] = byte(i + 1)
	for j := 1; j < 32; j++ {
		sender[j] = byte(0xaa + i)
	}
	return sender
}

func writeOutputs(dir string) error {
	kc := keychain()
	cases := []struct {
		vecIdx int
		index  uint32
		amount uint64
	}{
		{0, 0, 100_000},
		{1, 1, 200_000},
		{2, 10, 300_000},
	}
	for _, tc := range cases {
		sender := multiIndexSender(tc.vecIdx)
		out, _ := createOutput(&mweb.Recipient{
			Value:   tc.amount,
			Address: kc.Address(tc.index),
		}, sk(sender))
		var buf bytes.Buffer
		if err := out.Serialize(&buf); err != nil {
			return err
		}
		name := fmt.Sprintf("output_roundtrip_%d.hex", tc.index)
		if err := writeFile(dir, name, []byte(hex.EncodeToString(buf.Bytes())+"\n")); err != nil {
			return err
		}
	}
	dead := mustHex32("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	out, _ := createOutput(&mweb.Recipient{
		Value:   1_234_567,
		Address: kc.Address(0),
	}, sk(dead))
	var buf bytes.Buffer
	if err := out.Serialize(&buf); err != nil {
		return err
	}
	return writeFile(dir, "output_roundtrip_index0_deadbeef.hex", []byte(hex.EncodeToString(buf.Bytes())+"\n"))
}

func writeWrongScanOutput(dir string) error {
	kc := keychain()
	out, _ := createOutput(&mweb.Recipient{
		Value:   500_000,
		Address: kc.Address(0),
	}, sk(wrongKeySender))
	var buf bytes.Buffer
	if err := out.Serialize(&buf); err != nil {
		return err
	}
	return writeFile(dir, "output_wrong_scan_target.hex", []byte(hex.EncodeToString(buf.Bytes())+"\n"))
}

func writeSignMwebPsbt(dir string) error {
	kc := keychain()
	addrIdx := uint32(10)
	inputFeatures := wire.MwebInputStealthKeyFeatureBit
	pi := generateUnsignedPInput(inputFeatures, *kc.Address(addrIdx), sk(psbtInputSender), psbtOutputId)

	outputFeatures := wire.MwebOutputMessageStandardFieldsFeatureBit
	po := generateUnsignedPOutput(outputFeatures, sk(psbtOutputScan), sk(psbtOutputSpend))

	kernelFeatures := wire.MwebKernelStealthExcessFeatureBit | wire.MwebKernelFeeFeatureBit
	pk := generateUnsignedPKernel(kernelFeatures)

	packet := &psbt.Packet{
		PsbtVersion: 2,
		Inputs:      []psbt.PInput{*pi},
		Outputs:     []psbt.POutput{*po},
		Kernels:     []psbt.PKernel{*pk},
	}

	unsignedB64, err := packet.B64Encode()
	if err != nil {
		return err
	}
	if err := writeFile(dir, "psbt_sign_mweb_unsigned.base64", []byte(unsignedB64+"\n")); err != nil {
		return err
	}

	deriveOutputKeys := func(spentOutputPk *mw.PublicKey, keyExchangePubKey *mw.PublicKey, spentOutputSharedSecret *mw.SecretKey) (*mw.BlindingFactor, *mw.SecretKey, error) {
		sharedSecret := spentOutputSharedSecret
		if sharedSecret == nil {
			if keyExchangePubKey == nil {
				return nil, nil, fmt.Errorf("key exchange pubkey or shared secret needed")
			}
			sharedSecretPk := keyExchangePubKey.Mul(kc.Scan)
			sharedSecret = (*mw.SecretKey)(mw.Hashed(mw.HashTagDerive, sharedSecretPk[:]))
		}
		addrB := spentOutputPk.Div((*mw.SecretKey)(mw.Hashed(mw.HashTagOutKey, sharedSecret[:])))
		addrA := addrB.Mul(kc.Scan)
		address := mw.StealthAddress{Scan: addrA, Spend: addrB}
		if !address.Equal(kc.Address(addrIdx)) {
			return nil, nil, fmt.Errorf("address doesn't match")
		}
		preBlind := (*mw.BlindingFactor)(mw.Hashed(mw.HashTagBlind, sharedSecret[:]))
		outputSpendKey := kc.SpendKey(addrIdx).Mul((*mw.SecretKey)(mw.Hashed(mw.HashTagOutKey, sharedSecret[:])))
		return preBlind, outputSpendKey, nil
	}

	signer, err := psbt.NewSigner(packet, psbt.BasicMwebInputSigner{DeriveOutputKeys: deriveOutputKeys})
	if err != nil {
		return fmt.Errorf("NewSigner: %w", err)
	}
	outcome, err := signer.SignMwebComponents()
	if outcome != psbt.SignSuccesful || err != nil {
		return fmt.Errorf("SignMwebComponents: outcome=%v err=%v", outcome, err)
	}

	signedB64, err := packet.B64Encode()
	if err != nil {
		return err
	}
	if err := writeFile(dir, "psbt_sign_mweb_signed.base64", []byte(signedB64+"\n")); err != nil {
		return err
	}

	tx, err := psbt.Extract(packet)
	if err != nil {
		return fmt.Errorf("Extract: %w", err)
	}
	var txBuf bytes.Buffer
	if err := tx.Serialize(&txBuf); err != nil {
		return err
	}
	return writeFile(dir, "psbt_sign_mweb_extracted.hex", []byte(hex.EncodeToString(txBuf.Bytes())+"\n"))
}

func writeExtractValid(dir string) error {
	inputFeatures := wire.MwebInputFeatureBit(0)
	outputFeatures := wire.MwebOutputMessageFeatureBit(0)
	kernelFeatures := wire.MwebKernelFeatureBit(0)

	inSk := sk(mustHex32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	outSk := sk(mustHex32("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
	senderSk := sk(mustHex32("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"))
	kernelSk := sk(mustHex32("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"))

	commit := mw.NewCommitment((*mw.BlindingFactor)(inSk), 1)
	outCommit := mw.NewCommitment((*mw.BlindingFactor)(outSk), 1)
	excess := mw.NewCommitment((*mw.BlindingFactor)(kernelSk), 0)
	var oid chainhash.Hash
	copy(oid[:], psbtOutputId[:])

	emptyProof := secp256k1.RangeProof{}
	sigIn := mw.Sign(inSk, make([]byte, 32))
	sigOut := mw.Sign(senderSk, make([]byte, 32))
	sigK := mw.Sign(kernelSk, make([]byte, 32))
	zeroOffset := mw.BlindingFactor{}

	p := &psbt.Packet{
		PsbtVersion:       2,
		MwebTxOffset:      &zeroOffset,
		MwebStealthOffset: &zeroOffset,
		Inputs: []psbt.PInput{{
			MwebFeatures:     &inputFeatures,
			MwebCommit:       commit,
			MwebOutputId:     &oid,
			MwebInputPubkey:  inSk.PubKey(),
			MwebOutputPubkey: outSk.PubKey(),
			MwebInputSig:     &sigIn,
		}},
		Outputs: []psbt.POutput{{
			MwebFeatures:  &outputFeatures,
			OutputCommit:  outCommit,
			OutputPubkey:  outSk.PubKey(),
			SenderPubkey:  senderSk.PubKey(),
			RangeProof:    &emptyProof,
			MwebSignature: &sigOut,
		}},
		Kernels: []psbt.PKernel{{
			Features:         &kernelFeatures,
			ExcessCommitment: excess,
			Signature:        &sigK,
		}},
	}
	b64, err := p.B64Encode()
	if err != nil {
		return err
	}
	return writeFile(dir, "psbt_extract_valid_mweb.base64", []byte(b64+"\n"))
}

func generateUnsignedPInput(features wire.MwebInputFeatureBit, stealthAddress mw.StealthAddress, senderKey *mw.SecretKey, outputIdBytes [32]byte) *psbt.PInput {
	amount := ltcutil.Amount(123456)
	n := new(big.Int).SetBytes(mw.Hashed(mw.HashTagNonce, senderKey[:])[:16])
	h := blake3.New(32, nil)
	_ = binary.Write(h, binary.LittleEndian, mw.HashTagSendKey)
	_, _ = h.Write(stealthAddress.A()[:])
	_, _ = h.Write(stealthAddress.B()[:])
	_ = binary.Write(h, binary.LittleEndian, uint64(amount))
	_, _ = h.Write(n.FillBytes(make([]byte, 16)))
	s := (*mw.SecretKey)(h.Sum(nil))
	sA := stealthAddress.A().Mul(s)
	t := (*mw.SecretKey)(mw.Hashed(mw.HashTagDerive, sA[:]))
	Ko := stealthAddress.B().Mul((*mw.SecretKey)(mw.Hashed(mw.HashTagOutKey, t[:])))
	Ke := stealthAddress.B().Mul(s)
	mask := mw.OutputMaskFromShared(t)
	blind := mw.BlindSwitch(mask.Blind, uint64(amount))
	outputCommit := mw.NewCommitment(blind, uint64(amount))
	var outputId chainhash.Hash
	copy(outputId[:], outputIdBytes[:])
	return &psbt.PInput{
		MwebOutputId:          &outputId,
		MwebFeatures:          &features,
		MwebAmount:            &amount,
		MwebCommit:            outputCommit,
		MwebOutputPubkey:      Ko,
		MwebKeyExchangePubkey: Ke,
	}
}

func generateUnsignedPOutput(features wire.MwebOutputMessageFeatureBit, scanKey, spendKey *mw.SecretKey) *psbt.POutput {
	amount := ltcutil.Amount(345678)
	stealthAddress := mw.StealthAddress{Scan: scanKey.PubKey(), Spend: spendKey.PubKey()}
	return &psbt.POutput{
		Amount:         amount,
		StealthAddress: &stealthAddress,
		MwebFeatures:   &features,
	}
}

func generateUnsignedPKernel(features wire.MwebKernelFeatureBit) *psbt.PKernel {
	fee := ltcutil.Amount(10000)
	return &psbt.PKernel{
		Features: &features,
		Fee:      &fee,
	}
}

// createOutput mirrors unexported ltcd ltcutil/mweb.createOutput.
func createOutput(recipient *mweb.Recipient, senderKey *mw.SecretKey) (*wire.MwebOutput, *mw.BlindingFactor) {
	features := wire.MwebOutputMessageStandardFieldsFeatureBit
	n := new(big.Int).SetBytes(mw.Hashed(mw.HashTagNonce, senderKey[:])[:16])
	h := blake3.New(32, nil)
	_ = binary.Write(h, binary.LittleEndian, mw.HashTagSendKey)
	_, _ = h.Write(recipient.Address.A()[:])
	_, _ = h.Write(recipient.Address.B()[:])
	_ = binary.Write(h, binary.LittleEndian, recipient.Value)
	_, _ = h.Write(n.FillBytes(make([]byte, 16)))
	s := (*mw.SecretKey)(h.Sum(nil))
	sA := recipient.Address.A().Mul(s)
	t := (*mw.SecretKey)(mw.Hashed(mw.HashTagDerive, sA[:]))
	Ko := recipient.Address.B().Mul((*mw.SecretKey)(mw.Hashed(mw.HashTagOutKey, t[:])))
	Ke := recipient.Address.B().Mul(s)
	mask := mw.OutputMaskFromShared(t)
	blind := mw.BlindSwitch(mask.Blind, recipient.Value)
	mv := mask.MaskValue(recipient.Value)
	mn := mask.MaskNonce(n)
	outputCommit := mw.NewCommitment(blind, recipient.Value)
	Ks := senderKey.PubKey()
	viewTag := mw.Hashed(mw.HashTagTag, sA[:])[0]
	message := &wire.MwebOutputMessage{
		Features:          features,
		KeyExchangePubKey: *Ke,
		ViewTag:           viewTag,
		MaskedValue:       mv,
		MaskedNonce:       *mn,
	}
	var messageBuf bytes.Buffer
	_ = message.Serialize(&messageBuf)
	rangeProof := secp256k1.NewRangeProof(recipient.Value, *blind, make([]byte, 20), messageBuf.Bytes())
	rangeProofHash := blake3.Sum256(rangeProof[:])
	h = blake3.New(32, nil)
	_, _ = h.Write(outputCommit[:])
	_, _ = h.Write(Ks[:])
	_, _ = h.Write(Ko[:])
	_, _ = h.Write(message.Hash()[:])
	_, _ = h.Write(rangeProofHash[:])
	signature := mw.Sign(senderKey, h.Sum(nil))
	return &wire.MwebOutput{
		Commitment:     *outputCommit,
		SenderPubKey:   *Ks,
		ReceiverPubKey: *Ko,
		Message:        *message,
		RangeProof:     &rangeProof,
		RangeProofHash: rangeProofHash,
		Signature:      signature,
	}, mask.Blind
}
