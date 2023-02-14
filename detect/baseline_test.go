package detect

import (
	"errors"
	"fmt"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/zricethezav/gitleaks/v8/config"
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
	t.Run("", func(t *testing.T) {
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
	})
}
