package cmd

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
	"os"
	"time"
)

func init() {
	rootCmd.AddCommand(detectCmd)

	// Pass to Detect API
	detectCmd.Flags().Bool("follow-symlinks", false, "scan files that are symlinks to other files")
	detectCmd.Flags().StringSlice("gitleaks-ignore", []string{}, "pass paths to gitleaks ignore files explicitly.")
	detectCmd.Flags().Bool("exit-on-failed-ignore", true, "exit if Gitleaks fails to parse a gitleaks ignore file")

	// Do not pass to detect api
	detectCmd.Flags().Bool("no-git", false, "treat git repo as a regular directory and scan those files, --log-opts has no effect on the scan when --no-git is set")
	detectCmd.Flags().Bool("pipe", false, "scan input from stdin, ex: `cat some_file | gitleaks detect --pipe`")
}

var detectCmd = &cobra.Command{
	Use:   "detect",
	Short: "detect secrets in code",
	Run:   runDetect,
}

func runDetect(cmd *cobra.Command, args []string) {
	var (
		vc       config.ViperConfig
		findings []report.Finding
		err      error
	)

	// - git: scan the history of the repo
	// - no-git: scan files by treating the repo as a plain directory
	noGitMode, err := cmd.Flags().GetBool("no-git")
	if err != nil {
		log.Fatal().Err(err).Msg("could not call GetBool() for no-git")
	}

	pipeMode, err := cmd.Flags().GetBool("pipe")
	if err != nil {
		log.Fatal().Err(err)
	}

	if cmd.Flags().Changed("source") {
		log.Warn().Msgf("use of the --source flag is deprecated. pass file paths as command line args: ./gitleaks [opts...] <file_1> ... <file_n>")
		source, err := cmd.Flags().GetString("source")
		if err != nil {
			log.Fatal().Err(err)
		}

		args = append(args, source)
	}

	// TODO: Validate this works when pipe occurs.
	sourcePaths := config.LoadSourcePaths(args)

	if !noGitMode && !pipeMode && len(sourcePaths) > 1 {
		log.Fatal().Msgf("Cannot scan more than one git repository at a time. Pass one repo path, or use the --no-git flag")
	}

	parentConfig := initConfig(sourcePaths)
	// Load viper config
	err = viper.Unmarshal(&vc)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}
	cfg, err := vc.Translate(config.DetectType)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}

	// Write path to parent config
	cfg.SetParentPath(parentConfig)
	unmarshallCobraFlagsRoot(&cfg, cmd)
	unmarshallCobraFlagsDetect(&cfg, cmd)

	// start timer
	start := time.Now()

	// Setup detector
	detector := detect.NewDetector(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}

	if err = detector.AddIgnoreFilesFromConfig(); err != nil {
		log.Warn().Err(err)
	}
	if err = detector.AddBaselineFilesFromConfig(); err != nil {
		log.Warn().Err(err)
	}

	// TODO: Add warning about unbounded max memory size.
	// determine what type of scan:

	switch {
	case noGitMode:
		findings, err = detector.DetectFiles(sourcePaths)
		if err != nil {
			// don't exit on error, just log it
			log.Error().Err(err).Msg("")
		}
	case pipeMode:
		findings, err = detector.DetectReader(os.Stdin, 10)
		if err != nil {
			// log fatal to exit, no need to continue since a report
			// will not be generated when scanning from a pipe...for now
			log.Fatal().Err(err).Msg("")
		}
	default: // Default to scanning as git repository.
		findings, err = detector.DetectGit(sourcePaths[0], config.DetectType)
		if err != nil {
			// don't exit on error, just log it
			log.Error().Err(err).Msg("")
		}
	}

	// log info about the scan
	if err == nil {
		logScanSuccess(start, findings)
	} else {
		logScanFailure(start, findings)
	}

	// write report if desired
	reportPath, _ := cmd.Flags().GetString("report-path")
	ext, _ := cmd.Flags().GetString("report-format")
	if reportPath != "" {
		if err := report.Write(findings, cfg, ext, reportPath); err != nil {
			log.Fatal().Err(err).Msg("could not write")
		}
	}

	if err != nil {
		os.Exit(1)
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

func logScanFailure(start time.Time, findings []report.Finding) {
	log.Warn().Msgf("partial scan completed in %s", FormatDuration(time.Since(start)))
	if len(findings) != 0 {
		log.Warn().Msgf("%d leaks found in partial scan", len(findings))
	} else {
		log.Warn().Msg("no leaks found in partial scan")
	}
}

func logScanSuccess(start time.Time, findings []report.Finding) {
	log.Info().Msgf("scan completed in %s", FormatDuration(time.Since(start)))
	if len(findings) != 0 {
		log.Warn().Msgf("leaks found: %d", len(findings))
	} else {
		log.Info().Msg("no leaks found")
	}
}

func FormatDuration(d time.Duration) string {
	scale := 100 * time.Second
	// look for the max scale that is smaller than d
	for scale > d {
		scale /= 10
	}
	return d.Round(scale / 100).String()
}

// unmarshallCobraFlagsDetect updates a Detect API configuration structure with values passed by Cobra.
func unmarshallCobraFlagsDetect(cfg *config.Config, cmd *cobra.Command) {
	var err error

	symlinksChanged := cmd.Flags().Changed("follow-symlinks")
	symlinksSetByViper := viper.IsSet("FollowSymlinks")
	if symlinksChanged || !symlinksSetByViper {
		cfg.DetectConfig.FollowSymlinks, err = cmd.Flags().GetBool("follow-symlinks")
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to resolve value of 'follow-symlinks'")
		}
	}

	gitleakIgnoreChanged := cmd.Flags().Changed("gitleaks-ignore")
	gitleakIgnoreSetByViper := viper.IsSet("GitleaksIgnore")
	if gitleakIgnoreChanged || !gitleakIgnoreSetByViper {
		cfg.DetectConfig.GitleaksIgnore, err = cmd.Flags().GetStringSlice("gitleaks-ignore")
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to resolve value of 'gitleaks-ignore'")
		}
	}

	exitOnFailedIgnoreChanged := cmd.Flags().Changed("exit-on-failed-ignore")
	exitOnFailedIgnoreSetByViper := viper.IsSet("ExitOnFailedIgnore")
	if exitOnFailedIgnoreChanged || !exitOnFailedIgnoreSetByViper {
		cfg.DetectConfig.ExitOnFailedIgnore, err = cmd.Flags().GetBool("exit-on-failed-ignore")
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to resolve value of 'exit-on-failed-ignore'")
		}
	}

}
