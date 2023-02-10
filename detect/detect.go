package detect

import (
	"bufio"
	"context"
	"fmt"
	"github.com/h2non/filetype"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect/git"
	"github.com/zricethezav/gitleaks/v8/report"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/fatih/semgroup"
	"github.com/gitleaks/go-gitdiff/gitdiff"
	ahocorasick "github.com/petar-dambovaliev/aho-corasick"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

// Detector is the main detector struct
type Detector struct {
	// Config is the configuration for the detector
	Config config.Config

	// commitMap is used to keep track of commits that have been scanned.
	// This is only used for logging purposes and git scans.
	commitMap map[string]bool

	// findings is a thread safe slice of report.Findings. This is the result
	// of the detector's scan which can then be used to generate a
	// report.
	findings ThreadSafeSlice[report.Finding]

	// prefilter is a ahocorasick struct used for doing efficient string
	// matching given a set of words (keywords from the rules in the config)
	prefilter ahocorasick.AhoCorasick

	// a list of known findings that should be ignored
	baseline []report.Finding

	// gitleaksIgnore
	gitleaksIgnore map[string]bool

	// Mutex for concurrent map writes
	gitleaksIgnoreWriteMutex sync.Mutex
}

// Fragment contains the data to be scanned
type Fragment struct {
	// Raw is the raw content of the fragment
	Raw string

	// FilePath is the path to the file if applicable
	FilePath    string
	SymlinkFile string

	// CommitSHA is the SHA of the commit if applicable
	CommitSHA string

	// newlineIndices is a list of indices of newlines in the raw content.
	// This is used to calculate the line location of a finding
	newlineIndices [][]int

	// keywords is a map of all the keywords contain within the contents
	// of this fragment
	keywords map[string]bool
}

// NewDetector creates a new detector with the given config
func NewDetector(cfg config.Config) *Detector {
	builder := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{
		AsciiCaseInsensitive: true,
		MatchOnlyWholeWords:  false,
		MatchKind:            ahocorasick.LeftMostLongestMatch,
		DFA:                  true,
	})

	return &Detector{
		commitMap:                make(map[string]bool),
		gitleaksIgnore:           make(map[string]bool),
		gitleaksIgnoreWriteMutex: sync.Mutex{},
		findings:                 NewThreadSafeSlice([]report.Finding{}),
		Config:                   cfg,
		prefilter:                builder.Build(cfg.Keywords),
	}
}

// NewDetectorDefaultConfig creates a new detector with the default config
func NewDetectorDefaultConfig(scanType config.GitScanType) (*Detector, error) {
	viper.SetConfigType("toml")
	err := viper.ReadConfig(strings.NewReader(config.DefaultConfig))
	if err != nil {
		return nil, err
	}
	var vc config.ViperConfig
	err = viper.Unmarshal(&vc)
	if err != nil {
		return nil, err
	}
	cfg, err := vc.Translate(scanType)
	if err != nil {
		return nil, err
	}
	return NewDetector(cfg), nil
}

func (d *Detector) AddGitleaksIgnore(gitleaksIgnorePath string) error {
	file, err := os.Open(gitleaksIgnorePath)

	if err != nil {
		return err
	}
	log.Debug().Msg("found .gitleaksignore file")

	defer file.Close()
	scanner := bufio.NewScanner(file)

	d.gitleaksIgnoreWriteMutex.Lock()
	for scanner.Scan() {
		d.gitleaksIgnore[scanner.Text()] = true
	}
	d.gitleaksIgnoreWriteMutex.Unlock()

	return nil
}

func (d *Detector) AddBaseline(baselinePath string) error {
	if baselinePath != "" {
		baseline, err := LoadBaseline(baselinePath)
		if err != nil {
			return err
		}
		d.baseline = baseline
	}

	if added := d.Config.BaselinePath.Add(baselinePath); !added {
		return fmt.Errorf("failed to add baseline path: %v", baselinePath)
	}

	return nil
}

// DetectBytes scans the given bytes and returns a list of findings
func (d *Detector) DetectBytes(content []byte) []report.Finding {
	return d.DetectString(string(content))
}

// DetectString scans the given string and returns a list of findings
func (d *Detector) DetectString(content string) []report.Finding {
	return d.Detect(Fragment{
		Raw: content,
	})
}

// detectRule scans the given fragment for the given rule and returns a list of findings
func (d *Detector) detectRule(fragment Fragment, rule config.Rule) []report.Finding {
	var findings []report.Finding

	// check if filepath or commit is allowed for this rule
	if rule.Allowlist.CommitAllowed(fragment.CommitSHA) ||
		rule.Allowlist.PathAllowed(fragment.FilePath) {
		return findings
	}

	if rule.Path != nil && rule.Regex == nil {
		// Path _only_ rule
		if rule.Path.Match([]byte(fragment.FilePath)) {
			finding := report.Finding{
				Description: rule.Description,
				File:        fragment.FilePath,
				SymlinkFile: fragment.SymlinkFile,
				RuleID:      rule.RuleID,
				Match:       fmt.Sprintf("file detected: %s", fragment.FilePath),
				Tags:        rule.Tags,
			}
			return append(findings, finding)
		}
	} else if rule.Path != nil {
		// if path is set _and_ a regex is set, then we need to check both
		// so if the path does not match, then we should return early and not
		// consider the regex
		if !rule.Path.Match([]byte(fragment.FilePath)) {
			return findings
		}
	}

	// if path only rule, skip content checks
	if rule.Regex == nil {
		return findings
	}

	// If flag configure and raw data size bigger then the flag
	if d.Config.MaxTargetMegabytes > 0 {
		rawLength := len(fragment.Raw) / 1000000
		if rawLength > d.Config.MaxTargetMegabytes {
			log.Debug().Msgf("skipping file: %s scan due to size: %d", fragment.FilePath, rawLength)
			return findings
		}
	}

	matchIndices := rule.Regex.FindAllStringIndex(fragment.Raw, -1)

	for _, matchIndex := range matchIndices {
		// extract secret from match
		secret := strings.Trim(fragment.Raw[matchIndex[0]:matchIndex[1]], "\n")

		// determine location of match. Note that the location
		// in the finding will be the line/column numbers of the _match_
		// not the _secret_, which will be different if the secretGroup
		// value is set for this rule
		loc := location(fragment, matchIndex)

		if matchIndex[1] > loc.endLineIndex {
			loc.endLineIndex = matchIndex[1]
		}

		finding := report.Finding{
			Description: rule.Description,
			File:        fragment.FilePath,
			SymlinkFile: fragment.SymlinkFile,
			RuleID:      rule.RuleID,
			StartLine:   loc.startLine,
			EndLine:     loc.endLine,
			StartColumn: loc.startColumn,
			EndColumn:   loc.endColumn,
			Secret:      secret,
			Match:       secret,
			Tags:        rule.Tags,
			Lines:       fragment.Raw[loc.startLineIndex:loc.endLineIndex],
		}

		// check if the lines enclosing a finding contain any matches in the enclosing lines allowlist.
		if rule.Allowlist.EnclosingLinesRegexAllowed(finding.Lines) || d.Config.Allowlist.EnclosingLinesRegexAllowed(finding.Lines) {
			continue
		}

		// check if the secret is in the allowlist
		if rule.Allowlist.RegexAllowed(finding.Secret) ||
			d.Config.Allowlist.RegexAllowed(finding.Secret) {
			continue
		}

		// extract secret from secret group if set
		if rule.SecretGroup != 0 {
			groups := rule.Regex.FindStringSubmatch(secret)
			if len(groups) <= rule.SecretGroup || len(groups) == 0 {
				// Config validation should prevent this
				continue
			}
			secret = groups[rule.SecretGroup]
			finding.Secret = secret
		}

		// check if the secret is in the list of stopwords
		if rule.Allowlist.ContainsStopWord(finding.Secret) ||
			d.Config.Allowlist.ContainsStopWord(finding.Secret) {
			continue
		}

		// check entropy
		entropy := shannonEntropy(finding.Secret)
		finding.Entropy = float32(entropy)
		if rule.Entropy != 0.0 {
			if entropy <= rule.Entropy {
				// entropy is too low, skip this finding
				continue
			}
			// NOTE: this is a goofy hack to get around the fact there golang's regex engine
			// does not support positive lookaheads. Ideally we would want to add a
			// restriction on generic rules regex that requires the secret match group
			// contains both numbers and alphabetical characters, not just alphabetical characters.
			// What this bit of code does is check if the ruleid is prepended with "generic" and enforces the
			// secret contains both digits and alphabetical characters.
			// TODO: this should be replaced with stop words
			if strings.HasPrefix(rule.RuleID, "generic") {
				if !containsDigit(secret) {
					continue
				}
			}
		}

		findings = append(findings, finding)
	}
	return findings
}

// GitScan accepts a *gitdiff.File channel which contents a git history generated from
// the output of `git log -p ...`. startGitScan will look at each file (patch) in the history
// and determine if the patch contains any findings.
func (d *Detector) DetectGit(source string, logOpts string, gitScanType config.GitScanType) ([]report.Finding, error) {
	var (
		gitdiffFiles <-chan *gitdiff.File
		err          error
	)
	switch gitScanType {
	case config.DetectType:
		gitdiffFiles, err = git.GitLog(source, logOpts)
		if err != nil {
			return d.findings.slice, err
		}
	case config.ProtectType:
		gitdiffFiles, err = git.GitDiff(source, false)
		if err != nil {
			return d.findings.slice, err
		}
	case config.ProtectStagedType:
		gitdiffFiles, err = git.GitDiff(source, true)
		if err != nil {
			return d.findings.slice, err
		}
	}

	s := semgroup.NewGroup(context.Background(), int64(d.Config.MaxWorkers))

	for gitdiffFile := range gitdiffFiles {
		gitdiffFile := gitdiffFile

		// skip binary files
		if gitdiffFile.IsBinary || gitdiffFile.IsDelete {
			continue
		}

		// Check if commit is allowed
		commitSHA := ""
		if gitdiffFile.PatchHeader != nil {
			commitSHA = gitdiffFile.PatchHeader.SHA
			if d.Config.Allowlist.CommitAllowed(gitdiffFile.PatchHeader.SHA) {
				continue
			}
		}
		d.addCommit(commitSHA)

		s.Go(func() error {
			for _, textFragment := range gitdiffFile.TextFragments {
				if textFragment == nil {
					return nil
				}

				fragment := Fragment{
					Raw:       textFragment.Raw(gitdiff.OpAdd),
					CommitSHA: commitSHA,
					FilePath:  gitdiffFile.NewName,
				}

				for _, finding := range d.Detect(fragment) {
					d.addFinding(augmentGitFinding(finding, textFragment, gitdiffFile))
				}
			}
			return nil
		})
	}

	if err := s.Wait(); err != nil {
		return d.findings.slice, err
	}
	log.Info().Msgf("%d commits scanned.", len(d.commitMap))
	log.Debug().Msg("Note: this number might be smaller than expected due to commits with no additions")
	if git.ErrEncountered {
		return d.findings.slice, fmt.Errorf("%s", "git error encountered, see logs")
	}
	return d.findings.slice, nil
}

type scanTarget struct {
	Path    string
	Symlink string
}

// Scan a specific scanTarget
func (d *Detector) scanFilePath(target scanTarget) error {
	b, err := os.ReadFile(target.Path)
	if err != nil {
		return err
	}

	mimetype, err := filetype.Match(b)
	if err != nil {
		return err
	}
	if mimetype.MIME.Type == "application" {
		return nil // skip binary files
	}

	fragment := Fragment{
		Raw:      string(b),
		FilePath: target.Path,
	}

	if target.Symlink != "" {
		fragment.SymlinkFile = target.Symlink
	}

	for _, finding := range d.Detect(fragment) {
		// need to add 1 since line counting starts at 1
		finding.EndLine++
		finding.StartLine++

		log.Debug().Msgf("Finding found in %v", target.Path)
		d.addFinding(finding)
	}

	return nil
}

// DetectFiles accepts a path to a source directory or file and begins a scan of the
// file or directory.
func (d *Detector) DetectFiles(sources []string) ([]report.Finding, error) {
	sourcePathIterators := semgroup.NewGroup(context.Background(), int64(d.Config.MaxWorkers))
	paths := NewThreadSafeSlice(make([]scanTarget, 0))

	// Walk over each source path
	for _, source := range sources {
		sourcePathIterators.Go(func() error {
			return filepath.Walk(source,
				func(path string, fInfo os.FileInfo, err error) error {
					if err != nil {
						return err
					}
					if fInfo.Name() == ".git" && fInfo.IsDir() {
						return filepath.SkipDir
					}
					if fInfo.Size() == 0 {
						return nil
					}
					if fInfo.Mode().IsRegular() {
						// If the file is a .gitleaksignore file, add it to known fingerprints
						match, err := filepath.Match("*.gitleaksignore", path)
						if err != nil {
							return err
						}

						// Matches .gitleaksignore file.
						if match {
							if err := d.AddGitleaksIgnore(path); err == nil {
								return nil
							}
							log.Warn().Msgf("Failed to load gitleaks ignore file at %v", path)
						}

						// Otherwise, scan the file
						paths.Append(
							scanTarget{
								Path:    path,
								Symlink: "",
							})
					}
					if fInfo.Mode().Type() == fs.ModeSymlink && d.Config.DetectConfig.FollowSymlinks {
						realPath, err := filepath.EvalSymlinks(path)
						if err != nil {
							return err
						}
						realPathFileInfo, _ := os.Stat(realPath)

						if realPathFileInfo.IsDir() {
							log.Debug().Msgf("found symlinked directory: %s -> %s [skipping]", path, realPath)
							return nil
						}

						paths.Append(scanTarget{
							Path:    realPath,
							Symlink: path,
						})
					}
					return nil
				})
		})
	}

	// Wait for all paths to be enumerated.
	err := sourcePathIterators.Wait()
	if err != nil {
		log.Debug().Msgf("Finished with error")
		return d.findings.slice, err
	}

	// Scan each file concurrently.
	pathIterators := semgroup.NewGroup(context.Background(), int64(d.Config.MaxWorkers))

	for _, pa := range paths.slice {
		p := pa
		pathIterators.Go(func() error {
			return d.scanFilePath(p)
		})
	}

	if err := pathIterators.Wait(); err != nil {
		return d.findings.slice, err
	}

	return d.findings.slice, nil
}

// DetectReader accepts an io.Reader and a buffer size for the reader in KB
func (d *Detector) DetectReader(r io.Reader, bufSize int) ([]report.Finding, error) {
	reader := bufio.NewReader(r)
	buf := make([]byte, 0, 1000*bufSize)
	findings := []report.Finding{}

	for {
		n, err := reader.Read(buf[:cap(buf)])
		buf = buf[:n]
		if err != nil {
			if err != io.EOF {
				return findings, err
			}
			break
		}

		fragment := Fragment{
			Raw: string(buf),
		}
		for _, finding := range d.Detect(fragment) {
			findings = append(findings, finding)
			if d.Config.Verbose {
				printFinding(finding)
			}
		}
	}

	return findings, nil
}

// Detect scans the given fragment and returns a list of findings
func (d *Detector) Detect(fragment Fragment) []report.Finding {
	var findings []report.Finding

	// initiate fragment keywords
	fragment.keywords = make(map[string]bool)

	// check if filepath is allowed
	if fragment.FilePath != "" && (d.Config.Allowlist.PathAllowed(fragment.FilePath) ||
		fragment.FilePath == d.Config.Path || d.Config.BaselinePath.Contains(fragment.FilePath)) {
		return findings
	}

	// add newline indices for location calculation in detectRule
	fragment.newlineIndices = regexp.MustCompile("\n").FindAllStringIndex(fragment.Raw, -1)

	// build keyword map for prefiltering rules
	normalizedRaw := strings.ToLower(fragment.Raw)
	matches := d.prefilter.FindAll(normalizedRaw)
	for _, m := range matches {
		fragment.keywords[normalizedRaw[m.Start():m.End()]] = true
	}

	for _, rule := range d.Config.Rules {
		if len(rule.Keywords) == 0 {
			// if no keywords are associated with the rule always scan the
			// fragment using the rule
			findings = append(findings, d.detectRule(fragment, rule)...)
			continue
		}
		fragmentContainsKeyword := false
		// check if keywords are in the fragment
		for _, k := range rule.Keywords {
			if _, ok := fragment.keywords[strings.ToLower(k)]; ok {
				fragmentContainsKeyword = true
			}
		}
		if fragmentContainsKeyword {
			findings = append(findings, d.detectRule(fragment, rule)...)
		}
	}
	return filter(findings, d.Config.Redact)
}

// addFinding synchronously adds a finding to the findings slice
func (d *Detector) addFinding(finding report.Finding) {
	if finding.Commit == "" {
		finding.Fingerprint = fmt.Sprintf("%s:%s:%d", finding.File, finding.RuleID, finding.StartLine)
	} else {
		finding.Fingerprint = fmt.Sprintf("%s:%s:%s:%d", finding.Commit, finding.File, finding.RuleID, finding.StartLine)
	}
	// check if we should ignore this finding
	if _, ok := d.gitleaksIgnore[finding.Fingerprint]; ok {
		log.Debug().Msgf("ignoring finding with Fingerprint %s",
			finding.Fingerprint)
		return
	}

	if d.baseline != nil && !IsNew(finding, d.baseline) {
		log.Debug().Msgf("baseline duplicate -- ignoring finding with Fingerprint %s", finding.Fingerprint)
		return
	}

	d.findings.Append(finding)

	if d.Config.Verbose {
		printFinding(finding)
	}
}

// addCommit synchronously adds a commit to the commit slice
func (d *Detector) addCommit(commit string) {
	d.commitMap[commit] = true
}
