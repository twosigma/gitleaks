package detect

import (
	"errors"
	"fmt"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/zricethezav/gitleaks/v8/config"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zricethezav/gitleaks/v8/report"
)

func TestIsNew(t *testing.T) {
	tests := []struct {
		findings report.Finding
		baseline []report.Finding
		expect   bool
	}{
		{
			findings: report.Finding{
				Author: "a",
				Commit: "0000",
			},
			baseline: []report.Finding{
				{
					Author: "a",
					Commit: "0000",
				},
			},
			expect: false,
		},
		{
			findings: report.Finding{
				Author: "a",
				Commit: "0000",
			},
			baseline: []report.Finding{
				{
					Author: "a",
					Commit: "0002",
				},
			},
			expect: true,
		},
		{
			findings: report.Finding{
				Author: "a",
				Commit: "0000",
				Tags:   []string{"a", "b"},
			},
			baseline: []report.Finding{
				{
					Author: "a",
					Commit: "0000",
					Tags:   []string{"a", "c"},
				},
			},
			expect: false, // Updated tags doesn't make it a new finding
		},
	}
	for _, test := range tests {
		assert.Equal(t, test.expect, IsNew(test.findings, test.baseline))
	}
}

func TestFileLoadBaseline(t *testing.T) {
	tests := []struct {
		Filename      string
		ExpectedError error
	}{
		{
			Filename:      "../testdata/baseline/baseline.csv",
			ExpectedError: errors.New("the format of the file ../testdata/baseline/baseline.csv is not supported"),
		},
		{
			Filename:      "../testdata/baseline/baseline.sarif",
			ExpectedError: errors.New("the format of the file ../testdata/baseline/baseline.sarif is not supported"),
		},
		{
			Filename:      "../testdata/baseline/notfound.json",
			ExpectedError: errors.New("could not open ../testdata/baseline/notfound.json"),
		},
	}

	for _, test := range tests {
		_, err := LoadBaseline(test.Filename)
		assert.Equal(t, test.ExpectedError.Error(), err.Error())
	}
}

func TestIgnoreIssuesInBaseline(t *testing.T) {
	tests := []struct {
		findings    []report.Finding
		baseline    []report.Finding
		expectCount int
	}{
		{
			findings: []report.Finding{
				{
					Author: "a",
					Commit: "5",
				},
			},
			baseline: []report.Finding{
				{
					Author: "a",
					Commit: "5",
				},
			},
			expectCount: 0,
		},
		{
			findings: []report.Finding{
				{
					Author:      "a",
					Commit:      "5",
					Fingerprint: "a",
				},
			},
			baseline: []report.Finding{
				{
					Author:      "a",
					Commit:      "5",
					Fingerprint: "b",
				},
			},
			expectCount: 0,
		},
	}

	for _, test := range tests {
		d, _ := NewDetectorDefaultConfig(config.DetectType)
		d.baseline = test.baseline
		for _, finding := range test.findings {
			d.addFinding(finding)
		}
		assert.Equal(t, test.expectCount, len(d.findings.slice))
	}
}

func TestAddInvalidBaselineFilesFromConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  config.Config
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "nil_baselinePath",
			config: config.Config{
				BaselinePath: nil,
			},
			wantErr: assert.NoError,
		},
		{
			name: "invalid_baselinePath",
			config: config.Config{
				BaselinePath: mapset.NewSet[string]("/NON/EXISTENT/FILE/3789273892"),
			},
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewDetector(&tt.config)
			tt.wantErr(t, d.LoadBaselineFilesFromConfig(), fmt.Sprintf("LoadBaselineFilesFromConfig()"))
		})
	}
}

// Test that multiple valid baseline files can be read in using LoadBaselineFilesFromConfig.
func TestValidBaselineFilesFromConfig(t *testing.T) {
	config := config.Config{
		BaselinePath: mapset.NewSet[string]("../testdata/baseline/baseline.json", "../testdata/baseline/baseline2.json"),
	}
	d := NewDetector(&config)
	err := d.LoadBaselineFilesFromConfig()
	assert.Nil(t, err)

	assert.Len(t, d.baseline, 2)
	assert.Equal(t, 2, d.Config.BaselinePath.Cardinality())
	assert.Equal(t, 32, d.baseline[0].StartLine)
	assert.Equal(t, 33, d.baseline[1].StartLine)
}

// Tests that detector exits when in exit-on-failed-baseline is enabled.
func TestExitOnFailedBaseline(t *testing.T) {
	// Note: These tests won't show up in coverage ;(
	// https://stackoverflow.com/questions/26225513/how-to-test-os-exit-scenarios-in-go
	// https://go.dev/talks/2014/testing.slide#23
	if os.Getenv("CRASHING_PROCESS_LOAD_BASELINES_FROM_CONFIG") == "1" {
		config := config.Config{
			ExitOnFailedBaseline: true,
			BaselinePath:         mapset.NewSet[string]("../testdata/baseline/notfound.json"),
		}
		d := NewDetector(&config)
		d.LoadBaselineFilesFromConfig()
		return
	}

	if os.Getenv("CRASHING_PROCESS_ADD_BASELINES") == "1" {
		config := config.Config{
			ExitOnFailedBaseline: true,
		}
		d := NewDetector(&config)
		d.AddBaseline("../testdata/baseline/notfound.json")
		return
	}

	// Check that LoadBaselineFilesFromConfig fails
	cmd := exec.Command(os.Args[0], "-test.run=TestExitOnFailedBaselineLoad")
	cmd.Env = append(os.Environ(), "CRASHING_PROCESS_LOAD_BASELINES_FROM_CONFIG=1")
	err := cmd.Run()

	// Something went wrong if the process exited with 0, OR did not return an exit error.
	if e, ok := err.(*exec.ExitError); !ok || e.Success() {
		t.Fatalf("gitleaks FAILED to crash when exit-on-failed-baseline was enabled. LoadBaselineFilesFromConfig failed to crash")
	}

	// Check that AddBaseline fails
	cmd = exec.Command(os.Args[0], "-test.run=TestExitOnFailedBaselineLoad")
	cmd.Env = append(os.Environ(), "CRASHING_PROCESS_ADD_BASELINES=1")
	err = cmd.Run()

	// Something went wrong if the process exited with 0, OR did not return an exit error.
	if e, ok := err.(*exec.ExitError); !ok || e.Success() {
		t.Fatalf("gitleaks FAILED to crash when exit-on-failed-baseline was enabled. AddBaseline failed to crash.")
	}

}
