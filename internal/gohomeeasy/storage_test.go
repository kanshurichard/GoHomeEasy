package gohomeeasy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestFileStoragePreservesLegacyContentAcrossV2Writes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.json")
	if err := os.WriteFile(path, []byte("legacy-clash"), 0o600); err != nil {
		t.Fatalf("write legacy file: %v", err)
	}

	storage := NewFileStorage(path, "clash")

	legacy, err := storage.GetLegacySubscription("clash")
	if err != nil {
		t.Fatalf("read legacy subscription: %v", err)
	}
	if legacy != "legacy-clash" {
		t.Fatalf("expected legacy fallback content, got %q", legacy)
	}

	record := Record{
		RuleName:  "alpha",
		Type:      "ss",
		Host:      "edge.example.com",
		Port:      443,
		Method:    "aes-256-gcm",
		Password:  "secret",
		UpdatedAt: "2026-06-26T00:00:00Z",
	}
	if err := storage.PutRecord(record.RuleName, record); err != nil {
		t.Fatalf("put record: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved document: %v", err)
	}

	var document storageDocument
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode saved document: %v", err)
	}

	if document.Legacy["clash"] != "legacy-clash" {
		t.Fatalf("expected legacy clash content to be preserved, got %#v", document.Legacy)
	}
	if _, ok := document.Records["alpha"]; !ok {
		t.Fatalf("expected saved record alpha, got %#v", document.Records)
	}

	if err := storage.DeleteRecord("alpha"); err != nil {
		t.Fatalf("delete record: %v", err)
	}

	records, err := storage.ListRecords()
	if err != nil {
		t.Fatalf("list records after delete: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("expected empty record list after delete, got %#v", records)
	}

	legacyAfterDelete, err := storage.GetLegacySubscription("clash")
	if err != nil {
		t.Fatalf("read legacy after delete: %v", err)
	}
	if legacyAfterDelete != "legacy-clash" {
		t.Fatalf("expected legacy content after delete, got %q", legacyAfterDelete)
	}
}

func TestFileStorageReturnsNilForMissingRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.json")
	storage := NewFileStorage(path, "ss")

	record, err := storage.GetRecord("missing")
	if err != nil {
		t.Fatalf("get missing record: %v", err)
	}
	if record != nil {
		t.Fatalf("expected nil missing record, got %#v", record)
	}
}

func TestFileStorageConcurrentPutRecordPreservesAllRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.json")
	storage := NewFileStorage(path, "ss")

	const recordCount = 24

	start := make(chan struct{})
	errs := make(chan error, recordCount)
	var wg sync.WaitGroup

	for index := 0; index < recordCount; index++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start

			record := Record{
				RuleName:  fmt.Sprintf("node-%02d", index),
				Type:      "ss",
				Host:      fmt.Sprintf("edge-%02d.example.com", index),
				Port:      8000 + index,
				Method:    "aes-256-gcm",
				Password:  "secret",
				UpdatedAt: fmt.Sprintf("2026-06-26T00:00:%02dZ", index),
			}

			errs <- storage.PutRecord(record.RuleName, record)
		}(index)
	}

	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent put failed: %v", err)
		}
	}

	records, err := storage.ListRecords()
	if err != nil {
		t.Fatalf("list records after concurrent put: %v", err)
	}

	if len(records) != recordCount {
		t.Fatalf("expected %d records after concurrent puts, got %d", recordCount, len(records))
	}
}
