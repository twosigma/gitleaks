package cmd

import (
	"fmt"
	"github.com/zricethezav/gitleaks/v8/config"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const banner = `
    ○
    │╲
    │ ○
    ○ ░
    ░    gitleaks

`

const configDescription = `config file path
order of precedence:
1. --config/-c
2. env var GITLEAKS_CONFIG
3. sources passed on command line. (Defaults to $PWD)
If none of the three options are used, then gitleaks will use the default config`

var rootCmd = &cobra.Command{
	Use:   "gitleaks",
	Short: "Gitleaks scans code, past or present, for secrets",
}

func init() {
	cobra.OnInitialize(initLog)
	rootCmd.PersistentFlags().StringP("config", "c", "", configDescription)
	rootCmd.PersistentFlags().Int("exit-code", 1, "exit code when leaks have been encountered")
	rootCmd.PersistentFlags().IntP("max-workers", "j", 16, "maximum number of worker threads scanning files concurrently. Default value of 16")
	rootCmd.PersistentFlags().StringP("report-path", "r", "", "report file")
	rootCmd.PersistentFlags().StringP("report-format", "f", "json", "output format (json, csv, sarif)")
	rootCmd.PersistentFlags().StringSliceP("baseline-path", "b", []string{}, "path(s) to baseline file with issues that can be ignored")
	rootCmd.PersistentFlags().StringP("log-level", "l", "info", "log level (trace, debug, info, warn, error, fatal)")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "show verbose output from scan")
	rootCmd.PersistentFlags().Int("max-target-megabytes", 0, "files larger than this will be skipped")
	rootCmd.PersistentFlags().Bool("redact", false, "redact secrets from logs and stdout")
	rootCmd.PersistentFlags().Bool("no-banner", false, "suppress banner")
	rootCmd.PersistentFlags().Bool("no-exit-on-failed-baseline", false, "continue scanning even if Gitleaks fails to parse a baseline file")
	rootCmd.PersistentFlags().Bool("no-exit-on-failed-ignore", false, "continue scanning even if Gitleaks fails to parse a gitleaks ignore file")

	err := viper.BindPFlag("config", rootCmd.PersistentFlags().Lookup("config"))
	if err != nil {
		log.Fatal().Msgf("err binding config %s", err.Error())
	}

	err = viper.BindPFlag("maxworkers", rootCmd.PersistentFlags().Lookup("max-workers"))
	if err != nil {
		log.Fatal().Msgf("err binding max workers %s", err.Error())
	}
}

func initLog() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	ll, err := rootCmd.Flags().GetString("log-level")
	if err != nil {
		log.Fatal().Msg(err.Error())
	}
	switch strings.ToLower(ll) {
	case "trace":
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "err", "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	case "fatal":
		zerolog.SetGlobalLevel(zerolog.FatalLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}

func initConfig(sourcePaths []string) {
	hideBanner, err := rootCmd.Flags().GetBool("no-banner")
	if err != nil {
		log.Fatal().Msg(err.Error())
	}
	if !hideBanner {
		_, _ = fmt.Fprint(os.Stderr, banner)
	}
	cfgPath, err := rootCmd.Flags().GetString("config")
	if err != nil {
		log.Fatal().Msg(err.Error())
	}

	switch {
	case cfgPath != "":
		viper.SetConfigFile(cfgPath)
		log.Debug().Msgf("using gitleaks config %s from `--config`", cfgPath)
	case os.Getenv("GITLEAKS_CONFIG") != "":
		envPath := os.Getenv("GITLEAKS_CONFIG")
		viper.SetConfigFile(envPath)
		log.Debug().Msgf("using gitleaks config from GITLEAKS_CONFIG env var: %s", envPath)
	default:
		if len(sourcePaths) > 1 {
			log.Warn().Msg("multiple source files passed without explicitly specifying gitleaks configuration! using default config")
			config.LoadDefaultViperConfig()
			return
		}

		source := sourcePaths[0]
		sourcePath := filepath.Join(source, ".gitleaks.toml")

		fileInfo, err := os.Stat(source)
		if err != nil {
			log.Fatal().Msg(err.Error())
		}

		if !fileInfo.IsDir() {
			log.Debug().Msgf("unable to load gitleaks config from %s since --source=%s is a file, using default config",
				sourcePath, source)
			config.LoadDefaultViperConfig()
			return
		}

		if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
			log.Debug().Msgf("no gitleaks config found in path %s, using default gitleaks config", sourcePath)
			config.LoadDefaultViperConfig()
			return
		}

		log.Debug().Msgf("using existing gitleaks config %s from `(--source)/.gitleaks.toml`", sourcePath)
		viper.SetConfigFile(sourcePath)
	}

	// If this line is reached, default config not in use. As a result, viper needs to be instructed to read the file.
	if err := viper.ReadInConfig(); err != nil {
		log.Fatal().Msgf("unable to load gitleaks config, err: %s", err)
	}
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		if strings.Contains(err.Error(), "unknown flag") {
			// exit code 126: Command invoked cannot execute
			os.Exit(126)
		}
		log.Fatal().Msg(err.Error())
	}
}
