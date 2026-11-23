package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// A bare command name is looked up in PATH; an absolute path must already be clean.
var bareCommandName = regexp.MustCompile(`^[A-Za-z0-9._+-]+$`)

// validateRuntimeCommand rejects anything that is not a plain executable
// reference: a bare name, or a clean absolute path. The shim runs the command
// without a shell, but a spec with relative paths, "..", whitespace or control
// characters is never legitimate and is more likely a tampered file.
func validateRuntimeCommand(command string, args []string) error {
	if strings.ContainsRune(command, 0) {
		return errors.New("runtime-command.json 'command' contains a NUL byte")
	}
	if filepath.IsAbs(command) {
		if filepath.Clean(command) != command || strings.ContainsAny(command, " \t\r\n") {
			return fmt.Errorf("runtime-command.json 'command' %q is not a clean absolute path", command)
		}
	} else if !bareCommandName.MatchString(command) || command == "." || command == ".." {
		return fmt.Errorf("runtime-command.json 'command' %q must be a bare command name or an absolute path", command)
	}
	for _, arg := range args {
		if strings.ContainsRune(arg, 0) {
			return errors.New("runtime-command.json 'args' contains a NUL byte")
		}
	}
	return nil
}

type RuntimeCommandSpec struct {
	Command        string   `json:"command"`
	Args           []string `json:"args"`
	DetectCommand  string   `json:"detectCommand,omitempty"`
	InstallCommand string   `json:"installCommand,omitempty"`
}

func loadRuntimeCommandSpec(path string) (*RuntimeCommandSpec, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var spec RuntimeCommandSpec
	if err := json.Unmarshal(b, &spec); err != nil {
		return nil, err
	}
	if spec.Command == "" {
		return nil, errors.New("runtime-command.json has empty 'command'")
	}
	if err := validateRuntimeCommand(spec.Command, spec.Args); err != nil {
		return nil, err
	}
	return &spec, nil
}
