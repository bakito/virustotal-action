# Virus Total Action

Github action that downloads release assets extracts them an uploads the extracted binary as well as the archive to VirusTotal.
A link to the reports will be added to the release info.

## Example Action config

```yaml
name: Scan GitHub Release with VirusTotal

on:
  release:
    types: [released]

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
