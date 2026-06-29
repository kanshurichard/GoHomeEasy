package gohomeeasy

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	defaultListenAddr         = ":8080"
	defaultSubscriptionFormat = "ss"
	defaultStorePath          = "./data/records.json"
	defaultSessionTTLSeconds  = 86400
)

var defaultAllowedMethods = []string{
	"aes-128-cfb",
	"aes-192-cfb",
	"aes-256-cfb",
	"aes-128-gcm",
	"aes-192-gcm",
	"aes-256-gcm",
	"chacha20-ietf",
	"chacha20-ietf-poly1305",
	"xchacha20-ietf-poly1305",
	"2022-blake3-aes-128-gcm",
	"2022-blake3-aes-256-gcm",
	"2022-blake3-chacha20-poly1305",
}

type Config struct {
	AllowedMethods            map[string]struct{}
	DefaultSubscriptionFormat string
	ListenAddr                string
	ReadToken                 string
	SessionSecret             string
	SessionTTLSeconds         int64
	StoragePath               string
	WriteToken                string
}

func LoadConfigFromEnv() (Config, error) {
	defaultFormat := strings.ToLower(strings.TrimSpace(getEnv("SUBSCRIPTION_FORMAT", defaultSubscriptionFormat)))
	if defaultFormat != "ss" && defaultFormat != "clash" {
		return Config{}, fmt.Errorf("SUBSCRIPTION_FORMAT must be 'ss' or 'clash'")
	}

	readToken := strings.TrimSpace(os.Getenv("READ_TOKEN"))
	if readToken == "" {
		return Config{}, errors.New("READ_TOKEN is required")
	}

	writeToken := strings.TrimSpace(os.Getenv("WRITE_TOKEN"))
	if writeToken == "" {
		return Config{}, errors.New("WRITE_TOKEN is required")
	}

	storagePath := strings.TrimSpace(getEnv("STORAGE_PATH", defaultStorePath))
	if storagePath == "" {
		return Config{}, errors.New("STORAGE_PATH must not be empty")
	}

	listenAddr := strings.TrimSpace(getEnv("LISTEN_ADDR", defaultListenAddr))
	if listenAddr == "" {
		return Config{}, errors.New("LISTEN_ADDR must not be empty")
	}

	sessionTTLSeconds, err := parseSessionTTL(getEnv("SESSION_TTL_SECONDS", strconv.FormatInt(defaultSessionTTLSeconds, 10)))
	if err != nil {
		return Config{}, err
	}

	allowedMethods, err := parseAllowedMethods(os.Getenv("ALLOWED_METHODS"))
	if err != nil {
		return Config{}, err
	}

	return Config{
		AllowedMethods:            allowedMethods,
		DefaultSubscriptionFormat: defaultFormat,
		ListenAddr:                listenAddr,
		ReadToken:                 readToken,
		SessionSecret:             strings.TrimSpace(os.Getenv("SESSION_SECRET")),
		SessionTTLSeconds:         sessionTTLSeconds,
		StoragePath:               storagePath,
		WriteToken:                writeToken,
	}, nil
}

func parseAllowedMethods(raw string) (map[string]struct{}, error) {
	methods := map[string]struct{}{}

	if strings.TrimSpace(raw) == "" {
		for _, method := range defaultAllowedMethods {
			methods[method] = struct{}{}
		}
		return methods, nil
	}

	for _, part := range strings.Split(raw, ",") {
		method := strings.ToLower(strings.TrimSpace(part))
		if method == "" {
			continue
		}
		methods[method] = struct{}{}
	}

	if len(methods) == 0 {
		return nil, errors.New("ALLOWED_METHODS must contain at least one cipher")
	}

	return methods, nil
}

func parseSessionTTL(raw string) (int64, error) {
	value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || value < 60 {
		return 0, errors.New("SESSION_TTL_SECONDS must be an integer of at least 60")
	}

	return value, nil
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
