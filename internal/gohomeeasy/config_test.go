package gohomeeasy

import "testing"

func TestLoadConfigFromEnvAppliesV2Defaults(t *testing.T) {
	t.Setenv("READ_TOKEN", "read-token")
	t.Setenv("WRITE_TOKEN", "write-token")
	t.Setenv("SESSION_SECRET", "session-secret")
	t.Setenv("SESSION_TTL_SECONDS", "600")
	t.Setenv("ALLOWED_METHODS", "aes-256-gcm,chacha20-ietf-poly1305")

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.DefaultSubscriptionFormat != "ss" {
		t.Fatalf("expected default subscription format ss, got %q", cfg.DefaultSubscriptionFormat)
	}
	if cfg.StoragePath != "./data/records.json" {
		t.Fatalf("expected v2 default storage path, got %q", cfg.StoragePath)
	}
	if cfg.ListenAddr != ":8080" {
		t.Fatalf("expected default listen addr :8080, got %q", cfg.ListenAddr)
	}
	if cfg.SessionTTLSeconds != 600 {
		t.Fatalf("expected configured session ttl, got %d", cfg.SessionTTLSeconds)
	}
	if _, ok := cfg.AllowedMethods["aes-256-gcm"]; !ok {
		t.Fatalf("expected configured allowed methods to include aes-256-gcm")
	}
	if _, ok := cfg.AllowedMethods["chacha20-ietf-poly1305"]; !ok {
		t.Fatalf("expected configured allowed methods to include chacha20-ietf-poly1305")
	}
}

func TestLoadConfigFromEnvFailsClosedWhenRequiredSecretsMissing(t *testing.T) {
	t.Setenv("READ_TOKEN", "")
	t.Setenv("WRITE_TOKEN", "")

	if _, err := LoadConfigFromEnv(); err == nil {
		t.Fatalf("expected missing required token error")
	}
}
