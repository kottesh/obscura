package main

import (
	"context"
	"fmt"
)

// cmdConfig implements 'obscura config' and 'obscura config set <key> <value>'.
//
//	obscura config
//	    Print the effective (resolved) config to stdout: the config file path,
//	    the resolved server and host_key values, and where each came from. In
//	    --json mode it emits exactly one JSON object. It never prints secrets
//	    (server and host_key are not secret; the seed/private keys are never
//	    touched here).
//
//	obscura config set <key> <value>
//	    Create or update <config-dir>/obscura/config.toml (dir 0700, file 0600,
//	    atomic temp+rename), setting 'server' or 'host_key'. Unknown keys are a
//	    usage error. Comments and blank lines in an existing file are not
//	    preserved; the file is rewritten with only the known keys.
//
// Stream discipline (spec 8.3): the machine result goes to stdout; progress
// cards and errors go to stderr; --json emits one object on stdout.
func cmdConfig(_ context.Context, env *cmdEnv, args []string) error {
	fs := newFlagSet("config")
	if err := parseCmd(fs, args, 0, -1); err != nil {
		return err
	}
	rest := fs.Args()

	if len(rest) == 0 {
		return configShow(env)
	}
	if rest[0] != "set" {
		return usagef("config: unknown subcommand %q; use 'config' or 'config set <key> <value>'", rest[0])
	}
	if len(rest) != 3 {
		return usagef("config set: expected <key> <value>, got %d argument(s)", len(rest)-1)
	}
	return configSet(env, rest[1], rest[2])
}

// configSource labels where a resolved value came from, for the effective-config
// report. It never includes the value's provenance beyond flag/env/file/default.
func configSource(flagOrEnvOrFileValue, envValue, fileValue string) string {
	switch {
	case flagOrEnvOrFileValue == "":
		return "unset"
	case flagOrEnvOrFileValue == envValue && envValue != "":
		return "environment"
	case flagOrEnvOrFileValue == fileValue && fileValue != "":
		return "config file"
	default:
		return "flag"
	}
}

// configShow prints the effective config. Because parseGlobal already collapsed
// flag/env/file into g.server and g.hostKey, this re-reads env and file to
// attribute each resolved value's source for the human/JSON report.
func configShow(env *cmdEnv) error {
	path := configPath(env.g.configDir)
	fileCfg, _, err := loadConfig(env.g.configDir)
	if err != nil {
		return err
	}
	envServerVal := env.getenv(envServer)
	envHostKeyVal := env.getenv(envHostKey)

	serverSrc := configSource(env.g.server, envServerVal, fileCfg.server)
	hostKeySrc := configSource(env.g.hostKey, envHostKeyVal, fileCfg.hostKey)

	if env.g.mode == modeJSON() {
		return writeJSON(env.stdout, map[string]any{
			"version":         jsonVersion,
			"command":         "config",
			"config_path":     path,
			"config_dir":      env.g.configDir,
			"server":          env.g.server,
			"server_source":   serverSrc,
			"host_key":        env.g.hostKey,
			"host_key_source": hostKeySrc,
		})
	}

	fmt.Fprintf(env.stdout, "config_path: %s\n", path)
	fmt.Fprintf(env.stdout, "server: %s (%s)\n", displayValue(env.g.server), serverSrc)
	fmt.Fprintf(env.stdout, "host_key: %s (%s)\n", displayValue(env.g.hostKey), hostKeySrc)
	return nil
}

// displayValue renders an unset value as "(unset)" so the effective-config
// report is unambiguous.
func displayValue(v string) string {
	if v == "" {
		return "(unset)"
	}
	return v
}

// configSet writes key=value into the config file and confirms via a card to
// stderr (result to stdout in --json).
func configSet(env *cmdEnv, key, value string) error {
	path, err := writeConfigValue(env.g.configDir, key, value)
	if err != nil {
		return err
	}

	if env.g.mode == modeJSON() {
		return writeJSON(env.stdout, map[string]any{
			"version":     jsonVersion,
			"command":     "config set",
			"config_path": path,
			"key":         key,
			"value":       value,
		})
	}

	env.r.Success("Config updated", fmt.Sprintf("%s = %q in %s", key, value, path))
	return nil
}
