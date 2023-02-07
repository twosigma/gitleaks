package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

func init() {
	rootCmd.AddCommand(detectCmd)
	detectCmd.Flags().String("log-opts", "", "git log options")
	detectCmd.Flags().Bool("no-git", false, "treat git repo as a regular directory and scan those files, --log-opts has no effect on the scan when --no-git is set")
	detectCmd.Flags().Bool("pipe", false, "scan input from stdin, ex: `cat some_file | gitleaks detect --pipe`")
	detectCmd.Flags().Bool("follow-symlinks", false, "scan files that are symlinks to other files")
	detectCmd.Flags().StringSlice("gitleaks-ignore", []string{}, "Pass paths to gitleaks ignore files explicitly.")
}

var detectCmd = &cobra.Command{
	Use:   "detect",
	Short: "detect secrets in code",
	Run:   runDetect,
}

func runDetect(cmd *cobra.Command, args []string) {
	// TODO: Validate this works when pipe occurs.
	sourcePaths := config.LoadSourcePaths(args)
	initConfig(sourcePaths)
	var (
		vc       config.ViperConfig
		findings []report.Finding
		err      error
	)

	// Load config
	if err = viper.Unmarshal(&vc); err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}
	cfg, err := vc.Translate()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}
	// TODO: Make Path a list of paths.
	cfg.Path, _ = cmd.Flags().GetString("config")

	// start timer
	start := time.Now()

	// Setup detector
	detector := detect.NewDetector(cfg)
	detector.Config.Path, err = cmd.Flags().GetString("config")
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}

	// set verbose flag
	if detector.Verbose, err = cmd.Flags().GetBool("verbose"); err != nil {
		log.Fatal().Err(err).Msg("")
	}

	// set redact flag
	if detector.Redact, err = cmd.Flags().GetBool("redact"); err != nil {
		log.Fatal().Err(err).Msg("")
	}

	// set max target megabytes flag
	if detector.MaxTargetMegaBytes, err = cmd.Flags().GetInt("max-target-megabytes"); err != nil {
		log.Fatal().Err(err).Msg("")
	}

	// determine what type of scan:
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

	// TODO: Move this logic to pipe, and git section.
	// Add all gitleaksignore paths passed manually
	ignorePaths, _ := cmd.Flags().GetStringSlice("gitleaks-ignore")
	if !noGitMode {
		// Check the root directory for .gitleaksignore file.
		ignorePaths = append(ignorePaths, filepath.Join(sourcePaths[0], ".gitleaksignore"))
		log.Info().Msgf("Trying to ignore following paths: %v", ignorePaths)
	}

	noExitOnFailedIgnore, _ := cmd.Flags().GetBool("no-exit-on-failed-ignore")
	// Configure detector to ignore all provided paths.
	for _, ignorePath := range ignorePaths {
		// TODO: Make sure this works for absolute and relative paths. Make sure it works when gitleaks is invoked from another dir.
		if err = detector.AddGitleaksIgnore(ignorePath); err != nil {
			errMsg := fmt.Sprintf("Failed to register ignore file `%s` due to error: %s.", ignorePath, err)
			if !noExitOnFailedIgnore {
				log.Fatal().Msg(errMsg + "Use --no-exit-on-failed-ignore to continue scanning anyways.")
			}

			log.Error().Msg(errMsg)
		}
	}

	noExitOnFailedBaseline, _ := cmd.Flags().GetBool("no-exit-on-failed-baseline")
	// TODO: ignore findings from the baseline (an existing report in json format generated earlier)
	baselinePaths, _ := cmd.Flags().GetStringSlice("baseline-path")
	for _, baselinePath := range baselinePaths {
		if err := detector.AddBaseline(baselinePath); err != nil {
			errMsg := fmt.Sprintf("Could not load baseline at '%s'. The path must point of a gitleaks report generated using the default format: %s. ", baselinePath, err)

			if !noExitOnFailedBaseline {
				log.Fatal().Msg(errMsg + "Use --no-exit-on-failed-baseline to continue scanning anyways")
			}

			log.Error().Msg(errMsg)
		}
	}

	// set follow symlinks flag
	if detector.FollowSymlinks, err = cmd.Flags().GetBool("follow-symlinks"); err != nil {
		log.Fatal().Err(err).Msg("")
	}

	// set exit code
	exitCode, err := cmd.Flags().GetInt("exit-code")
	if err != nil {
		log.Fatal().Err(err).Msg("could not get exit code")
	}

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
		var logOpts string
		logOpts, err = cmd.Flags().GetString("log-opts")
		if err != nil {
			log.Fatal().Err(err).Msg("")
		}
		// TODO: Add an args function that check that if we are scanning git repo it implies there is only one source.
		findings, err = detector.DetectGit(sourcePaths[0], logOpts, detect.DetectType)
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
