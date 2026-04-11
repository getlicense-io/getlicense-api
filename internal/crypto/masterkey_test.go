package crypto

import (
	"bytes"
	"testing"
)

const testHexKey = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" +
	"2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"

func TestNewMasterKey_Valid(t *testing.T) {
	mk, err := NewMasterKey(testHexKey)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if mk == nil {
		t.Fatal("expected non-nil MasterKey")
	}
	if len(mk.HMACKey) != 32 {
		t.Errorf("HMACKey: expected 32 bytes, got %d", len(mk.HMACKey))
	}
	if len(mk.EncryptionKey) != 32 {
		t.Errorf("EncryptionKey: expected 32 bytes, got %d", len(mk.EncryptionKey))
	}
	if len(mk.JWTSigningKey) != 32 {
		t.Errorf("JWTSigningKey: expected 32 bytes, got %d", len(mk.JWTSigningKey))
	}
}

func TestNewMasterKey_TooShort(t *testing.T) {
	_, err := NewMasterKey("0102030405060708090a0b0c0d0e0f10")
	if err == nil {
		t.Fatal("expected error for too-short key, got nil")
	}
}

func TestNewMasterKey_InvalidHex(t *testing.T) {
	_, err := NewMasterKey("gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg")
	if err == nil {
		t.Fatal("expected error for invalid hex, got nil")
	}
}

func TestNewMasterKey_Deterministic(t *testing.T) {
	mk1, err := NewMasterKey(testHexKey)
	if err != nil {
		t.Fatal(err)
	}
	mk2, err := NewMasterKey(testHexKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mk1.HMACKey, mk2.HMACKey) {
		t.Error("HMACKey not deterministic")
	}
	if !bytes.Equal(mk1.EncryptionKey, mk2.EncryptionKey) {
		t.Error("EncryptionKey not deterministic")
	}
	if !bytes.Equal(mk1.JWTSigningKey, mk2.JWTSigningKey) {
		t.Error("JWTSigningKey not deterministic")
	}
}

func TestNewMasterKey_DerivedKeysDiffer(t *testing.T) {
	mk, err := NewMasterKey(testHexKey)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(mk.HMACKey, mk.EncryptionKey) {
		t.Error("HMACKey and EncryptionKey should differ")
	}
	if bytes.Equal(mk.HMACKey, mk.JWTSigningKey) {
		t.Error("HMACKey and JWTSigningKey should differ")
	}
	if bytes.Equal(mk.EncryptionKey, mk.JWTSigningKey) {
		t.Error("EncryptionKey and JWTSigningKey should differ")
	}
}
