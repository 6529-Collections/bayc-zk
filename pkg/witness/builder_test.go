package witness

import (
	"path/filepath"
	"testing"
)

func TestFromFixtures(t *testing.T) {
	// Load test fixtures from the testdata directory
	testdataDir := filepath.Join("testdata")
	
	builder, err := FromFixtures(testdataDir)
	if err != nil {
		t.Fatalf("FromFixtures failed: %v", err)
	}
	
	// Assert that all required fields are populated with non-empty slices
	if len(builder.AccountProof) == 0 {
		t.Error("AccountProof should not be empty")
	}
	
	if len(builder.AccountPath) == 0 {
		t.Error("AccountPath should not be empty")
	}
	
	if len(builder.StorageProof) == 0 {
		t.Error("StorageProof should not be empty")
	}
	
	if len(builder.StoragePath) == 0 {
		t.Error("StoragePath should not be empty")
	}
	
	if builder.StateRoot == nil {
		t.Error("StateRoot should not be nil")
	}
	
	if builder.Owner == "" {
		t.Error("Owner should not be empty")
	}
	
	if builder.TokenID == nil {
		t.Error("TokenID should not be nil")
	}
	
	if len(builder.OwnerBytes) == 0 {
		t.Error("OwnerBytes should not be empty")
	}
	
	// Additional checks for expected values
	if builder.TokenID.Int64() != 8822 {
		t.Errorf("Expected TokenID 8822, got %d", builder.TokenID.Int64())
	}
	
	if len(builder.Owner) != 40 { // 20 bytes = 40 hex characters
		t.Errorf("Expected Owner to be 40 hex characters, got %d", len(builder.Owner))
	}
	
	if len(builder.OwnerBytes) != 32 { // Should be 32 bytes for storage slot
		t.Errorf("Expected OwnerBytes to be 32 bytes, got %d", len(builder.OwnerBytes))
	}
	
	// Log some basic info for verification
	t.Logf("AccountProof has %d nodes", len(builder.AccountProof))
	t.Logf("StorageProof has %d nodes", len(builder.StorageProof))
	t.Logf("AccountPath has %d nibbles", len(builder.AccountPath))
	t.Logf("StoragePath has %d nibbles", len(builder.StoragePath))
	t.Logf("TokenID: %s", builder.TokenID.String())
	t.Logf("Owner: %s", builder.Owner)
	t.Logf("OwnerBytes: %d bytes (all zeros for empty slot)", len(builder.OwnerBytes))
}

func TestFromFixtures_MissingFiles(t *testing.T) {
	// Test with non-existent directory
	_, err := FromFixtures("nonexistent")
	if err == nil {
		t.Error("Expected error when loading from non-existent directory")
	}
}