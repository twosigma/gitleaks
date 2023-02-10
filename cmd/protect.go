package cmd

import (
	"os"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

func init() {
	// Pass to detect API

	// Don't pass to detect API
	protectCmd.Flags().Bool("staged", false, "detect secrets in a --staged state")
	rootCmd.AddCommand(protectCmd)
}

var protectCmd = &cobra.Command{
	Use:   "protect",
	Short: "protect secrets in code",
	Run:   runProtect,
}

func runProtect(cmd *cobra.Command, args []string) {
	sourcePaths := config.LoadSourcePaths(args)
	parentConfig := initConfig(sourcePaths)
	exitCode, _ := cmd.Flags().GetInt("exit-code")
	staged, _ := cmd.Flags().GetBool("staged")

	var mode config.GitScanType
	if staged {
		mode = config.ProtectStagedType
	} else {
		mode = config.ProtectType
	}

	var vc config.ViperConfig

	if err := viper.Unmarshal(&vc); err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}
	cfg, err := vc.Translate(mode)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}

	cfg.Path.Add(parentConfig)
	unmarshallCobraFlagsRoot(&cfg, cmd)
	unmarshallCobraFlagsDetect(&cfg, cmd)

	start := time.Now()

	// Setup detector
	detector := detect.NewDetector(cfg)

	// start git scan
	var findings []report.Finding
	findings, err = detector.DetectGit(sourcePaths[0], mode)

	if err != nil {
		// don't exit on error, just log it
		log.Error().Err(err).Msg("")
	}

	// log info about the scan
	log.Info().Msgf("scan completed in %s", FormatDuration(time.Since(start)))
	if len(findings) != 0 {
		log.Warn().Msgf("leaks found: %d", len(findings))
	} else {
		log.Info().Msg("no leaks found")
	}

	reportPath, _ := cmd.Flags().GetString("report-path")
	ext, _ := cmd.Flags().GetString("report-format")
	if reportPath != "" {
		if err = report.Write(findings, cfg, ext, reportPath); err != nil {
			log.Fatal().Err(err).Msg("")
		}
	}
	if len(findings) != 0 {
		os.Exit(exitCode)
	}
}

// unmarshallCobraFlagsProtect updates a Detect API configuration structure with values passed by Cobra.
func unmarshallCobraFlagsProtect(cfg *config.Config, cmd *cobra.Command) {}
