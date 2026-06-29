package gohomeeasy

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type storageDocument struct {
	Version int               `json:"version"`
	Records map[string]Record `json:"records"`
	Legacy  map[string]string `json:"legacy,omitempty"`
}

type FileStorage struct {
	defaultFormat string
	mu            sync.RWMutex
	path          string
}

func NewFileStorage(path string, defaultFormat string) *FileStorage {
	return &FileStorage{
		defaultFormat: defaultFormat,
		path:          path,
	}
}

func (s *FileStorage) DeleteRecord(ruleName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	document, err := s.loadDocument()
	if err != nil {
		return err
	}
	delete(document.Records, ruleName)
	return s.saveDocument(document)
}

func (s *FileStorage) GetLegacySubscription(subtype string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	document, err := s.loadDocument()
	if err != nil {
		return "", err
	}
	return document.Legacy[subtype], nil
}

func (s *FileStorage) GetRecord(ruleName string) (*Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	document, err := s.loadDocument()
	if err != nil {
		return nil, err
	}
	record, ok := document.Records[ruleName]
	if !ok {
		return nil, nil
	}
	return &record, nil
}

func (s *FileStorage) ListRecords() ([]Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	document, err := s.loadDocument()
	if err != nil {
		return nil, err
	}

	records := make([]Record, 0, len(document.Records))
	for _, record := range document.Records {
		records = append(records, record)
	}
	return records, nil
}

func (s *FileStorage) PutRecord(ruleName string, record Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	document, err := s.loadDocument()
	if err != nil {
		return err
	}
	document.Records[ruleName] = record
	return s.saveDocument(document)
}

func (s *FileStorage) loadDocument() (storageDocument, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return storageDocument{
				Version: 2,
				Records: map[string]Record{},
				Legacy:  map[string]string{},
			}, nil
		}
		return storageDocument{}, err
	}

	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return storageDocument{
			Version: 2,
			Records: map[string]Record{},
			Legacy:  map[string]string{},
		}, nil
	}

	var document storageDocument
	if err := json.Unmarshal(data, &document); err == nil && (document.Version == 2 || document.Records != nil || document.Legacy != nil) {
		if document.Records == nil {
			document.Records = map[string]Record{}
		}
		if document.Legacy == nil {
			document.Legacy = map[string]string{}
		}
		document.Version = 2
		return document, nil
	}

	legacy := map[string]string{}
	if s.defaultFormat == "ss" || s.defaultFormat == "clash" {
		legacy[s.defaultFormat] = string(data)
	}

	return storageDocument{
		Version: 2,
		Records: map[string]Record{},
		Legacy:  legacy,
	}, nil
}

func (s *FileStorage) saveDocument(document storageDocument) error {
	document.Version = 2
	if document.Records == nil {
		document.Records = map[string]Record{}
	}
	if document.Legacy == nil {
		document.Legacy = map[string]string{}
	}

	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}

	tempFile, err := os.CreateTemp(filepath.Dir(s.path), "records-*.tmp")
	if err != nil {
		return err
	}
	tempPath := tempFile.Name()

	if _, err := tempFile.Write(data); err != nil {
		tempFile.Close()
		_ = os.Remove(tempPath)
		return err
	}

	if err := tempFile.Chmod(0o600); err != nil {
		tempFile.Close()
		_ = os.Remove(tempPath)
		return err
	}

	if err := tempFile.Close(); err != nil {
		_ = os.Remove(tempPath)
		return err
	}

	if err := os.Rename(tempPath, s.path); err != nil {
		_ = os.Remove(tempPath)
		return err
	}

	return nil
}

func deriveRecordStorageKey(ruleName string) string {
	return "record:v2:" + base64.RawURLEncoding.EncodeToString([]byte(ruleName))
}
