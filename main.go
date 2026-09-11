package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/bakito/virustotal-action/pkg/action"
	"github.com/bakito/virustotal-action/pkg/types"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		flagReleaseName     string
		flagVTApiKey        string
		flagArtifactPattern string
		flagBinaryPattern   string
		flagPollInterval    string
		flagPollMaxAttempts string
		flagGitHubToken     string
		flagGitHubRepo      string
		flagUpdateToLatest  string
	)

	flag.StringVar(&flagReleaseName, "release-name", "", "The github release name")
	flag.StringVar(&flagVTApiKey, "vt-api-key", "", "The VirusTotal API Key")
	flag.StringVar(
		&flagArtifactPattern,
		"download-release-artifact-pattern",
		"",
		"Download only assets that match a glob pattern",
	)
	flag.StringVar(&flagBinaryPattern, "binary-pattern", "", "Pattern to select binary files for upload")
	flag.StringVar(&flagPollInterval, "poll-interval-seconds", "", "How many seconds to wait between polling VirusTotal")
	flag.StringVar(&flagPollMaxAttempts, "poll-max-attempts", "", "Maximum number of polling attempts")
	flag.StringVar(&flagGitHubToken, "github-token", "", "GitHub token for API access")
	flag.StringVar(&flagGitHubRepo, "repo", "", "GitHub repository (owner/repo)")
	flag.StringVar(
		&flagUpdateToLatest,
		"update-to-latest",
		"",
		"Enable transition from pre-release to latest if all checks are successful",
	)

	flag.Parse()

	releaseName := cmp.Or(flagReleaseName, os.Getenv("INPUT_RELEASE_NAME"), os.Getenv("RELEASE_NAME"))
	vtAPIKey := cmp.Or(flagVTApiKey, os.Getenv("INPUT_VT_API_KEY"), os.Getenv("VT_API_KEY"))
	artifactPattern := cmp.Or(
		flagArtifactPattern,
		os.Getenv("INPUT_DOWNLOAD_RELEASE_ARTIFACT_PATTERN"),
		os.Getenv("DOWNLOAD_RELEASE_ARTIFACT_PATTERN"),
		"*windows*",
	)
	binaryPattern := cmp.Or(flagBinaryPattern, os.Getenv("INPUT_BINARY_PATTERN"), os.Getenv("BINARY_PATTERN"), "*.exe")
	pollIntervalStr := cmp.Or(
		flagPollInterval,
		os.Getenv("INPUT_POLL_INTERVAL_SECONDS"),
		os.Getenv("POLL_INTERVAL_SECONDS"),
		"30",
	)
	pollMaxAttemptsStr := cmp.Or(
		flagPollMaxAttempts,
		os.Getenv("INPUT_POLL_MAX_ATTEMPTS"),
		os.Getenv("POLL_MAX_ATTEMPTS"),
		"20",
	)
	githubToken := cmp.Or(flagGitHubToken, os.Getenv("INPUT_GITHUB_TOKEN"), os.Getenv("GITHUB_TOKEN"), os.Getenv("GH_TOKEN"))
	githubRepo := cmp.Or(flagGitHubRepo, os.Getenv("INPUT_GITHUB_REPOSITORY"), os.Getenv("GITHUB_REPOSITORY"))
	updateToLatestStr := cmp.Or(
		flagUpdateToLatest,
		os.Getenv("INPUT_UPDATE_TO_LATEST"),
		os.Getenv("INPUT_PRERELEASE_TO_LATEST"),
		os.Getenv("INPUT_TRANSITION_TO_LATEST"),
		os.Getenv("UPDATE_TO_LATEST"),
		os.Getenv("PRERELEASE_TO_LATEST"),
		os.Getenv("TRANSITION_TO_LATEST"),
		"false",
	)

	if releaseName == "" {
		return errors.New("'release_name' input is required but not provided")
	}
	if vtAPIKey == "" {
		return errors.New("'vt_api_key' input is required but not provided")
	}

	pollIntervalSec, err := strconv.Atoi(pollIntervalStr)
	if err != nil || pollIntervalSec <= 0 {
		pollIntervalSec = 30
	}

	pollMaxAttempts, err := strconv.Atoi(pollMaxAttemptsStr)
	if err != nil || pollMaxAttempts <= 0 {
		pollMaxAttempts = 20
	}

	updateToLatest, _ := strconv.ParseBool(updateToLatestStr)

	cfg := &types.Config{
		ReleaseName:                    releaseName,
		VTApiKey:                       vtAPIKey,
		DownloadReleaseArtifactPattern: artifactPattern,
		BinaryPattern:                  binaryPattern,
		PollInterval:                   time.Duration(pollIntervalSec) * time.Second,
		PollMaxAttempts:                pollMaxAttempts,
		GitHubToken:                    githubToken,
		GitHubRepository:               githubRepo,
		UpdateToLatest:                 updateToLatest,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	runner := &action.Runner{}
	return runner.Run(ctx, cfg)
}
