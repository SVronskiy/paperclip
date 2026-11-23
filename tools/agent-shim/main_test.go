package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRuntimeCommandSpec_OK(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "spec.json")
	_ = os.WriteFile(p, []byte(`{"command":"claude-code","args":["--print"]}`), 0o600)
	spec, err := loadRuntimeCommandSpec(p)
	if err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
	if spec.Command != "claude-code" || len(spec.Args) != 1 {
		t.Fatalf("unexpected spec: %+v", spec)
	}
}

func TestLoadRuntimeCommandSpec_MissingCommand(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "spec.json")
	_ = os.WriteFile(p, []byte(`{"command":""}`), 0o600)
	if _, err := loadRuntimeCommandSpec(p); err == nil {
		t.Fatal("expected error for empty command")
	}
}

func TestLoadRuntimeCommandSpec_RejectsUnsafeCommands(t *testing.T) {
	cases := map[string]string{
		"relative path":    `{"command":"./claude"}`,
		"parent traversal": `{"command":"../bin/claude"}`,
		"shell metachar":   `{"command":"claude;rm -rf /"}`,
		"whitespace":       `{"command":"claude --print"}`,
		"unclean absolute": `{"command":"/usr/bin/../bin/claude"}`,
		"nul in command":   `{"command":"claude\u0000"}`,
		"nul in args":      `{"command":"claude","args":["a\u0000b"]}`,
		"dot":              `{"command":"."}`,
	}
	for name, body := range cases {
		dir := t.TempDir()
		p := filepath.Join(dir, "spec.json")
		_ = os.WriteFile(p, []byte(body), 0o600)
		if _, err := loadRuntimeCommandSpec(p); err == nil {
			t.Fatalf("%s: expected the spec to be rejected", name)
		}
	}
}

func TestLoadRuntimeCommandSpec_AcceptsBareNamesAndCleanAbsolutePaths(t *testing.T) {
	for _, command := range []string{"claude", "claude-code", "codex", "cursor-agent", "/usr/local/bin/claude"} {
		dir := t.TempDir()
		p := filepath.Join(dir, "spec.json")
		_ = os.WriteFile(p, []byte(`{"command":"`+command+`","args":["--print","a b"]}`), 0o600)
		if _, err := loadRuntimeCommandSpec(p); err != nil {
			t.Fatalf("%s: expected ok, got %v", command, err)
		}
	}
}
