package config

import (
	_ "embed"
	"fmt"
	mapset "github.com/deckarep/golang-set/v2"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

//go:embed gitleaks.toml
var DefaultConfig string

// use to keep track of how many configs we can extend
// yea I know, globals bad
var extendDepth int

const maxExtendDepth = 2
const gitleaksAllowSignature = "gitleaks:allow"

// GitScanType is used to differentiate between git scan types:
// $ gitleaks detect
// $ gitleaks protect
// $ gitleaks protect staged
type GitScanType int

const (
	DetectType GitScanType = iota
	ProtectType
	ProtectStagedType
)

// ViperConfig is the config struct used by the Viper config package
// to parse the config file. This struct does not include regular expressions.
// It is used as an intermediary to convert the Viper config to the Config struct.
type ViperConfig struct {

	// Non command-line fields
	Description string
	Extend      Extend
	Rules       []struct {
		ID          string
		Description string
		Entropy     float64
		SecretGroup int
		Regex       string
		Keywords    []string
		Path        string
		Tags        []string

		Allowlist struct {
			Regexes               []string
			EnclosingLinesRegexes []string
			Paths                 []string
			Commits               []string
			StopWords             []string
		}
	}
	Allowlist struct {
		Regexes               []string
		EnclosingLinesRegexes []string
		Paths                 []string
		Commits               []string
		StopWords             []string
	}

	// Root command line fields
	// Root command Detector API Flags
	MaxWorkers           uint
	BaselinePath         []string
	Verbose              bool
	MaxTargetMegabytes   uint
	Redact               bool
	GitLogOpts           string
	ExitOnFailedBaseline bool
	ExitOnFailedIgnore   bool

	// Detect command line fields
	FollowSymlinks bool
	GitleaksIgnore []string

	// Protect command line fields.
	// NONE
}

// Config contains parameters determining how the DetectAPI behaves across all modes
type Config struct {
	Extend      Extend
	Path        string
	Description string
	Rules       map[string]Rule
	Allowlist   Allowlist
	Keywords    []string

	// Used to keep sarif results consistent
	orderedRules []string

	// Paths to baseline files
	BaselinePath mapset.Set[string]

	// Git log options
	GitLogOpts string

	// Files larger than this will be skipped
	MaxTargetMegabytes uint

	// Maximum number of GoRoutines allowed to scan concurrently
	MaxWorkers uint

	// Redact is a flag to redact findings.
	Redact bool

	// Verbose is a flag to print findings
	Verbose bool

	// ExitOnFailedBaseline indicates if Detector API should exit when a baseline file fails to be registered.
	ExitOnFailedBaseline bool

	// Detect mode specific configuration
	DetectConfig *DetectConfig

	// Protect mode specific configuration
	ProtectConfig *ProtectConfig
}

// DetectConfig contains parameters determining how DetectAPI behaves in DetectType mode
type DetectConfig struct {
	// FollowSymlinks is a flag that enables scanning of symlink files
	FollowSymlinks bool

	// Paths to gitleaks ignore files.
	GitleaksIgnore []string

	// ExitOnFailedIgnore indicates if Detector API should exit when a gitleaks ignore file fails to be registered.
	ExitOnFailedIgnore bool
}

// ProtectConfig contains parameters determining how DetectAPI behaves in ProtectType/ProtectTypeStaged mode
type ProtectConfig struct {
}

// Extend is a struct that allows users to define how they want their
// configuration extended by other configuration files.
type Extend struct {
	Path       string
	URL        string
	UseDefault bool
}

func (vc *ViperConfig) Translate(scanType GitScanType) (Config, error) {
	var (
		keywords     []string
		orderedRules []string
	)
	rulesMap := make(map[string]Rule)

	for _, r := range vc.Rules {

		allowlistRegexes := compileRegexPatterns(r.Allowlist.Regexes)
		allowlistEnclosingLinesRegexes := compileRegexPatterns(r.Allowlist.EnclosingLinesRegexes)
		allowlistPaths := compileRegexPatterns(r.Allowlist.Paths)

		if r.Keywords == nil {
			r.Keywords = []string{}
		} else {
			for _, k := range r.Keywords {
				keywords = append(keywords, strings.ToLower(k))
			}
		}

		if r.Tags == nil {
			r.Tags = []string{}
		}

		var configRegex *regexp.Regexp
		var configPathRegex *regexp.Regexp
		if r.Regex == "" {
			configRegex = nil
		} else {
			configRegex = regexp.MustCompile(r.Regex)
		}
		if r.Path == "" {
			configPathRegex = nil
		} else {
			configPathRegex = regexp.MustCompile(r.Path)
		}
		r := Rule{
			Description: r.Description,
			RuleID:      r.ID,
			Regex:       configRegex,
			Path:        configPathRegex,
			SecretGroup: r.SecretGroup,
			Entropy:     r.Entropy,
			Tags:        r.Tags,
			Keywords:    r.Keywords,
			Allowlist: Allowlist{
				Regexes:               allowlistRegexes,
				EnclosingLinesRegexes: allowlistEnclosingLinesRegexes,
				Paths:                 allowlistPaths,
				Commits:               r.Allowlist.Commits,
				StopWords:             r.Allowlist.StopWords,
			},
		}
		orderedRules = append(orderedRules, r.RuleID)

		if r.Regex != nil && r.SecretGroup > r.Regex.NumSubexp() {
			return Config{}, fmt.Errorf("%s invalid regex secret group %d, max regex secret group %d", r.Description, r.SecretGroup, r.Regex.NumSubexp())
		}
		rulesMap[r.RuleID] = r
	}

	allowlistRegexes := compileRegexPatterns(vc.Allowlist.Regexes)
	allowlistPaths := compileRegexPatterns(vc.Allowlist.Paths)

	enclosingLinesPatterns := append(vc.Allowlist.EnclosingLinesRegexes, gitleaksAllowSignature)
	allowlistEnclosingLinesRegexes := compileRegexPatterns(enclosingLinesPatterns)

	c := Config{
		Description: vc.Description,
		Extend:      vc.Extend,
		Rules:       rulesMap,
		Allowlist: Allowlist{
			Regexes:               allowlistRegexes,
			EnclosingLinesRegexes: allowlistEnclosingLinesRegexes,
			Paths:                 allowlistPaths,
			Commits:               vc.Allowlist.Commits,
			StopWords:             vc.Allowlist.StopWords,
		},
		Keywords:     keywords,
		orderedRules: orderedRules,

		MaxWorkers:           vc.MaxWorkers,
		BaselinePath:         mapset.NewSet[string](vc.BaselinePath...),
		Verbose:              vc.Verbose,
		MaxTargetMegabytes:   vc.MaxTargetMegabytes,
		Redact:               vc.Redact,
		GitLogOpts:           vc.GitLogOpts,
		ExitOnFailedBaseline: vc.ExitOnFailedBaseline,
	}

	if scanType == DetectType {
		c.DetectConfig = &DetectConfig{
			FollowSymlinks:     vc.FollowSymlinks,
			GitleaksIgnore:     vc.GitleaksIgnore,
			ExitOnFailedIgnore: vc.ExitOnFailedIgnore,
		}
	}

	if scanType == ProtectType || scanType == ProtectStagedType {
		c.ProtectConfig = &ProtectConfig{}
	}

	if maxExtendDepth != extendDepth {
		// disallow both usedefault and path from being set
		if c.Extend.Path != "" && c.Extend.UseDefault {
			log.Fatal().Msg("unable to load config due to extend.path and extend.useDefault being set")
		}
		if c.Extend.UseDefault {
			c.extendDefault(scanType)
		} else if c.Extend.Path != "" {
			c.extendPath(scanType)
		}

	}

	return c, nil
}

func compileRegexPatterns(patterns []string) []*regexp.Regexp {
	var compiledRegexes []*regexp.Regexp
	for _, pattern := range patterns {
		compiledRegexes = append(compiledRegexes, regexp.MustCompile(pattern))
	}

	return compiledRegexes
}

func (c *Config) OrderedRules() []Rule {
	var orderedRules []Rule
	for _, id := range c.orderedRules {
		if _, ok := c.Rules[id]; ok {
			orderedRules = append(orderedRules, c.Rules[id])
		}
	}
	return orderedRules
}

func (c *Config) extendDefault(scanType GitScanType) {
	extendDepth++
	viper.SetConfigType("toml")
	if err := viper.ReadConfig(strings.NewReader(DefaultConfig)); err != nil {
		log.Fatal().Msgf("failed to load extended config, err: %s", err)
		return
	}
	defaultViperConfig := ViperConfig{}
	if err := viper.Unmarshal(&defaultViperConfig); err != nil {
		log.Fatal().Msgf("failed to load extended config, err: %s", err)
		return
	}
	cfg, err := defaultViperConfig.Translate(scanType)
	if err != nil {
		log.Fatal().Msgf("failed to load extended config, err: %s", err)
		return
	}
	log.Debug().Msg("extending config with default config")
	c.extend(cfg)

}

func (c *Config) extendPath(scanType GitScanType) {
	extendDepth++
	viper.SetConfigFile(c.Extend.Path)
	if err := viper.ReadInConfig(); err != nil {
		log.Fatal().Msgf("failed to load extended config, err: %s", err)
		return
	}
	extensionViperConfig := ViperConfig{}
	if err := viper.Unmarshal(&extensionViperConfig); err != nil {
		log.Fatal().Msgf("failed to load extended config, err: %s", err)
		return
	}
	cfg, err := extensionViperConfig.Translate(scanType)
	if err != nil {
		log.Fatal().Msgf("failed to load extended config, err: %s", err)
		return
	}
	log.Debug().Msgf("extending config with %s", c.Extend.Path)
	c.extend(cfg)
}

func (c *Config) extend(extensionConfig Config) {
	for ruleID, rule := range extensionConfig.Rules {
		if _, ok := c.Rules[ruleID]; !ok {
			log.Trace().Msgf("adding %s to base config", ruleID)
			c.Rules[ruleID] = rule
			c.Keywords = append(c.Keywords, rule.Keywords...)
		}
	}

	// append allowlists, not attempting to merge
	c.Allowlist.Commits = append(c.Allowlist.Commits,
		extensionConfig.Allowlist.Commits...)
	c.Allowlist.Paths = append(c.Allowlist.Paths,
		extensionConfig.Allowlist.Paths...)
	c.Allowlist.Regexes = append(c.Allowlist.Regexes,
		extensionConfig.Allowlist.Regexes...)
	c.Allowlist.EnclosingLinesRegexes = append(c.Allowlist.EnclosingLinesRegexes,
		extensionConfig.Allowlist.EnclosingLinesRegexes...)
}

func LoadSourcePaths(sources []string) []string {
	if len(sources) == 0 {
		return []string{"."}
	}

	return sources
}

// Loads default viper config.
func LoadDefaultViperConfig() {
	viper.SetConfigType("toml")
	if err := viper.ReadConfig(strings.NewReader(DefaultConfig)); err != nil {
		log.Fatal().Msgf("err reading default config toml %s", err.Error())
	}
}
