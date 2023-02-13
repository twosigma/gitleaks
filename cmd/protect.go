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
	staged, _ := cmd.Flags().GetBool("staged")

	sourcePaths := config.LoadSourcePaths(args)
	parentConfig := initConfig(sourcePaths)

	var mode config.GitScanType
	if staged {
		mode = config.ProtectStagedType
	} else {
		mode = config.ProtectType
	}

	start := time.Now()
	var vc config.ViperConfig

	if err := viper.Unmarshal(&vc); err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}
	cfg, err := vc.Translate(mode)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}

	cfg.SetParentPath(parentConfig)
	unmarshallCobraFlagsRoot(&cfg, cmd)
	unmarshallCobraFlagsProtect(&cfg, cmd)

	// Setup detector
	detector := detect.NewDetector(cfg)

	if err = detector.AddBaselineFilesFromConfig(); err != nil {
		log.Warn().Err(err)
	}

	// start git scan
	var findings []report.Finding
	findings, err = detector.DetectGit(sourcePaths[0], mode)
	duration := FormatDuration(time.Since(start))

	// log info about scan.
	if err == nil {
		logScanSuccess(duration, findings)
	} else {
		logScanFailure(duration, findings)
	}

	reportPath, _ := cmd.Flags().GetString("report-path")
	ext, _ := cmd.Flags().GetString("report-format")
	if reportPath != "" {
		if err = report.Write(findings, cfg, ext, reportPath); err != nil {
			log.Fatal().Err(err).Msg("")
		}
	}

	// set exit code
	exitCode, err := cmd.Flags().GetInt("exit-code")
	if err != nil {
		log.Fatal().Err(err).Msg("could not get exit code")
	}

	if len(findings) != 0 {
		os.Exit(exitCode)
	}
}

// unmarshallCobraFlagsProtect updates a Detect API configuration structure with values passed by Cobra.
func unmarshallCobraFlagsProtect(cfg *config.Config, cmd *cobra.Command) {}
