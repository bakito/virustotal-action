# Virus Total Action

Github action that downloads release assets extracts them an uploads the extracted binary as well as the archive to VirusTotal.
A link to the reports will be added to the release info. Optionally, if `update_to_latest` is enabled and the release is a pre-release and all checks are successful, the release is transitioned to latest.

## Inputs

| Input | Description | Required | Default |
| --- | --- | --- | --- |
| `release_name` | The GitHub release name (e.g., `${{ github.event.release.tag_name }}`). | **true** | |
| `vt_api_key` | The VirusTotal API Key (e.g., `${{ secrets.VT_API_KEY }}`). | **true** | |
| `download_release_artifact_pattern` | Download only assets that match a glob pattern. | `false` | `*windows*` |
| `binary_pattern` | Pattern to select binary files for upload. | `false` | `*.exe` |
| `poll_interval_seconds` | How many seconds to wait between polling VirusTotal for analysis status. | `false` | `30` |
| `poll_max_attempts` | Maximum number of polling attempts before giving up on a scan. | `false` | `20` |
| `github_token` | GitHub Token for API access. | `false` | `${{ github.token }}` |
| `update_to_latest` | Enable transition from pre-release to latest if all checks are successful. | `false` | `false` |

## Example Action config

### Run on release

```yaml
name: Scan GitHub Release with VirusTotal

on:
  release:
    types: [prereleased, released]

jobs:
  scan_release:
    runs-on: ubuntu-latest

    steps:
      - name: Analyze Build Assets
        uses: bakito/virustotal-action@main
        with:
          release_name: ${{github.event.release.tag_name}}
          vt_api_key: ${{secrets.VT_API_KEY}}

```

### Periodically re scan latest release

```yaml
name: Scan GitHub Release with VirusTotal

on:
  release:
    types: [released]
  schedule:
    - cron: '30 3 * * *'
  workflow_dispatch:
    inputs:
      release_tag:
        description: 'Release tag to scan (optional, defaults to latest)'
        required: false
        default: ''

jobs:
  scan_release:
    runs-on: ubuntu-latest
    steps:
      - name: Get Latest Release Tag
        id: latest_release
        run: |
          RELEASE_TAG=${{ github.event.release.tag_name }}
          if [ -z "$RELEASE_TAG" ]; then
            RELEASE_TAG=${{ github.event.inputs.release_tag }}
          fi
          if [ -z "$RELEASE_TAG" ]; then
            RELEASE_TAG=$(curl -s https://api.github.com/repos/${{ github.repository }}/releases/latest | jq -r '.tag_name')
          fi
          echo "tag_name=$RELEASE_TAG" >> $GITHUB_OUTPUT

      - name: Analyze Build Assets
        uses: bakito/virustotal-action@f27c5bc29fedcfc124c12e1c37a91bfb0a20276f # v1.0.3
        with:
          release_name: ${{ steps.latest_release.outputs.tag_name }}
          vt_api_key: ${{secrets.VT_API_KEY}}
```
