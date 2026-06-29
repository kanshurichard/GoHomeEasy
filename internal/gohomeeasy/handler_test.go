package gohomeeasy

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHandlerPreservesLegacyFallbackUntilSSRecordExists(t *testing.T) {
	storagePath := filepath.Join(t.TempDir(), "subscription.txt")
	legacyShadowsocksURI := "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzQGVkZ2UuZXhhbXBsZS5jb206ODM4OA==#legacy"
	if err := os.WriteFile(storagePath, []byte(legacyShadowsocksURI), 0o600); err != nil {
		t.Fatalf("write legacy file: %v", err)
	}

	cfg := Config{
		AllowedMethods:            mustAllowedMethods(t, ""),
		DefaultSubscriptionFormat: "ss",
		ListenAddr:                ":0",
		ReadToken:                 "read-token",
		SessionSecret:             "session-secret",
		SessionTTLSeconds:         86400,
		StoragePath:               storagePath,
		WriteToken:                "write-token",
	}

	handler := NewHandler(cfg, log.New(io.Discard, "", 0))

	legacyRequest := httptest.NewRequest(http.MethodGet, "http://example.com/?api_key=read-token", nil)
	legacyRecorder := httptest.NewRecorder()
	handler.ServeHTTP(legacyRecorder, legacyRequest)

	decodedLegacy, err := base64.StdEncoding.DecodeString(legacyRecorder.Body.String())
	if err != nil {
		t.Fatalf("decode legacy subscription: %v", err)
	}

	if legacyRecorder.Code != http.StatusOK || string(decodedLegacy) != legacyShadowsocksURI {
		t.Fatalf("expected legacy fallback, got %d %s", legacyRecorder.Code, legacyRecorder.Body.String())
	}

	siteRequest := httptest.NewRequest(http.MethodPost, "http://example.com/webhook", strings.NewReader(`{"ruleName":"portal","type":"site","host":"portal.example.com","port":8443}`))
	siteRequest.Header.Set("Authorization", "Bearer write-token")
	siteRecorder := httptest.NewRecorder()
	handler.ServeHTTP(siteRecorder, siteRequest)

	if siteRecorder.Code != http.StatusOK {
		t.Fatalf("expected site upsert success, got %d %s", siteRecorder.Code, siteRecorder.Body.String())
	}

	legacyAfterSiteRequest := httptest.NewRequest(http.MethodGet, "http://example.com/?api_key=read-token", nil)
	legacyAfterSiteRecorder := httptest.NewRecorder()
	handler.ServeHTTP(legacyAfterSiteRecorder, legacyAfterSiteRequest)

	decodedLegacyAfterSite, err := base64.StdEncoding.DecodeString(legacyAfterSiteRecorder.Body.String())
	if err != nil {
		t.Fatalf("decode legacy subscription after site: %v", err)
	}

	if legacyAfterSiteRecorder.Code != http.StatusOK || string(decodedLegacyAfterSite) != legacyShadowsocksURI {
		t.Fatalf("expected legacy fallback after site record, got %d %s", legacyAfterSiteRecorder.Code, legacyAfterSiteRecorder.Body.String())
	}

	ssRequest := httptest.NewRequest(http.MethodPost, "http://example.com/webhook", strings.NewReader(`{"ruleName":"alpha","ipAddr":"[2001:db8::1]:8388","method":"chacha20-ietf-poly1305","password":"密码123"}`))
	ssRequest.Header.Set("Authorization", "Bearer write-token")
	ssRecorder := httptest.NewRecorder()
	handler.ServeHTTP(ssRecorder, ssRequest)

	if ssRecorder.Code != http.StatusOK {
		t.Fatalf("expected ss upsert success, got %d %s", ssRecorder.Code, ssRecorder.Body.String())
	}

	subscriptionRequest := httptest.NewRequest(http.MethodGet, "http://example.com/?api_key=read-token", nil)
	subscriptionRecorder := httptest.NewRecorder()
	handler.ServeHTTP(subscriptionRecorder, subscriptionRequest)

	if subscriptionRecorder.Code != http.StatusOK {
		t.Fatalf("expected v2 subscription, got %d %s", subscriptionRecorder.Code, subscriptionRecorder.Body.String())
	}

	decoded, err := base64.StdEncoding.DecodeString(subscriptionRecorder.Body.String())
	if err != nil {
		t.Fatalf("decode subscription: %v", err)
	}

	if string(decoded) != "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTrlr4bnoIExMjNAWzIwMDE6ZGI4OjoxXTo4Mzg4#alpha" {
		t.Fatalf("unexpected decoded subscription: %s", string(decoded))
	}
}

func TestHandlerDashboardCookieAndDeleteFlow(t *testing.T) {
	cfg := Config{
		AllowedMethods:            mustAllowedMethods(t, ""),
		DefaultSubscriptionFormat: "ss",
		ListenAddr:                ":0",
		ReadToken:                 "read-token",
		SessionSecret:             "session-secret",
		SessionTTLSeconds:         86400,
		StoragePath:               filepath.Join(t.TempDir(), "subscription.txt"),
		WriteToken:                "write-token",
	}

	handler := NewHandler(cfg, log.New(io.Discard, "", 0))

	for _, payload := range []string{
		`{"ruleName":"alpha","ip":"edge.example.com","port":443,"method":"aes-256-gcm","password":"secret"}`,
		`{"ruleName":"portal","type":"site","host":"portal.example.com","port":8443}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "http://panel.example.com/webhook", strings.NewReader(payload))
		request.Header.Set("Authorization", "Bearer write-token")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("seed record failed: %d %s", recorder.Code, recorder.Body.String())
		}
	}

	loginRequest := httptest.NewRequest(http.MethodGet, "https://panel.example.com/dashboard?api_key=write-token", nil)
	loginRequest.Header.Set("X-Forwarded-Proto", "https")
	loginRecorder := httptest.NewRecorder()
	handler.ServeHTTP(loginRecorder, loginRequest)

	if loginRecorder.Code != http.StatusFound {
		t.Fatalf("expected dashboard login redirect, got %d %s", loginRecorder.Code, loginRecorder.Body.String())
	}

	cookies := loginRecorder.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookieName {
		t.Fatalf("expected session cookie, got %#v", cookies)
	}

	recordsRequest := httptest.NewRequest(http.MethodGet, "https://panel.example.com/api/records", nil)
	recordsRequest.AddCookie(cookies[0])
	recordsRequest.Header.Set("X-Forwarded-Proto", "https")
	recordsRecorder := httptest.NewRecorder()
	handler.ServeHTTP(recordsRecorder, recordsRequest)

	if recordsRecorder.Code != http.StatusOK {
		t.Fatalf("expected records api success, got %d %s", recordsRecorder.Code, recordsRecorder.Body.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(recordsRecorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode records payload: %v", err)
	}

	if payload["mode"] != "write" {
		t.Fatalf("expected write mode, got %#v", payload["mode"])
	}

	records := payload["records"].([]any)
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}

	deleteWithoutOrigin := httptest.NewRequest(http.MethodPost, "https://panel.example.com/api/delete", strings.NewReader(`{"ruleName":"alpha"}`))
	deleteWithoutOrigin.AddCookie(cookies[0])
	deleteWithoutOrigin.Header.Set("X-Forwarded-Proto", "https")
	deleteWithoutOriginRecorder := httptest.NewRecorder()
	handler.ServeHTTP(deleteWithoutOriginRecorder, deleteWithoutOrigin)

	if deleteWithoutOriginRecorder.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden delete without origin, got %d", deleteWithoutOriginRecorder.Code)
	}

	deleteWithOrigin := httptest.NewRequest(http.MethodPost, "https://panel.example.com/api/delete", strings.NewReader(`{"ruleName":"alpha"}`))
	deleteWithOrigin.AddCookie(cookies[0])
	deleteWithOrigin.Header.Set("Origin", "https://panel.example.com")
	deleteWithOrigin.Header.Set("X-Forwarded-Proto", "https")
	deleteWithOriginRecorder := httptest.NewRecorder()
	handler.ServeHTTP(deleteWithOriginRecorder, deleteWithOrigin)

	if deleteWithOriginRecorder.Code != http.StatusNoContent {
		t.Fatalf("expected successful delete, got %d %s", deleteWithOriginRecorder.Code, deleteWithOriginRecorder.Body.String())
	}
}

func TestHandlerAddressValidationAndHeaderAuth(t *testing.T) {
	cfg := Config{
		AllowedMethods:            mustAllowedMethods(t, ""),
		DefaultSubscriptionFormat: "clash",
		ListenAddr:                ":0",
		ReadToken:                 "read-token",
		SessionSecret:             "session-secret",
		SessionTTLSeconds:         86400,
		StoragePath:               filepath.Join(t.TempDir(), "subscription.txt"),
		WriteToken:                "write-token",
	}

	handler := NewHandler(cfg, log.New(io.Discard, "", 0))

	invalidPriorityRequest := httptest.NewRequest(http.MethodPost, "http://example.com/webhook", strings.NewReader(`{"ruleName":"broken","ip":"bad host","host":"good.example.com","port":443,"method":"aes-256-gcm","password":"secret"}`))
	invalidPriorityRequest.Header.Set("Authorization", "Bearer write-token")
	invalidPriorityRecorder := httptest.NewRecorder()
	handler.ServeHTTP(invalidPriorityRecorder, invalidPriorityRequest)

	if invalidPriorityRecorder.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid ip rejection, got %d %s", invalidPriorityRecorder.Code, invalidPriorityRecorder.Body.String())
	}

	seedRequest := httptest.NewRequest(http.MethodPost, "http://example.com/webhook", strings.NewReader(`{"ruleName":"edge","ipAddr":"edge.example.com:9443","method":"aes-256-gcm","password":"secret"}`))
	seedRequest.Header.Set("Authorization", "Bearer write-token")
	seedRecorder := httptest.NewRecorder()
	handler.ServeHTTP(seedRecorder, seedRequest)

	if seedRecorder.Code != http.StatusOK {
		t.Fatalf("expected seed success, got %d %s", seedRecorder.Code, seedRecorder.Body.String())
	}

	headerAuthRequest := httptest.NewRequest(http.MethodGet, "http://example.com/api/records?api_key=read-token", nil)
	headerAuthRequest.Header.Set("Authorization", "Bearer read-token")
	headerAuthRecorder := httptest.NewRecorder()
	handler.ServeHTTP(headerAuthRecorder, headerAuthRequest)

	if headerAuthRecorder.Code != http.StatusOK {
		t.Fatalf("expected header auth success, got %d %s", headerAuthRecorder.Code, headerAuthRecorder.Body.String())
	}

	queryOnlyRequest := httptest.NewRequest(http.MethodGet, "http://example.com/api/records?api_key=read-token", nil)
	queryOnlyRecorder := httptest.NewRecorder()
	handler.ServeHTTP(queryOnlyRecorder, queryOnlyRequest)

	if queryOnlyRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected query-only api auth rejection, got %d", queryOnlyRecorder.Code)
	}
}

func mustAllowedMethods(t *testing.T, raw string) map[string]struct{} {
	t.Helper()

	methods, err := parseAllowedMethods(raw)
	if err != nil {
		t.Fatalf("parse allowed methods: %v", err)
	}

	return methods
}
