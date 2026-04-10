# Palo Alto GlobalProtect Stats Tracker

A PHP CLI application to fetch GlobalProtect gateway statistics and track successful/unsuccessful logins by geo-region.

## Setup

1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```
2. Update `.env` with your firewall URL and API key.
3. Install dependencies:
   ```bash
   composer dump-autoload
   ```
4. Update the geo-location cache (first run):
   ```bash
   ./bin/pangpstats --update-geo
   ```

## Usage

Run the script to fetch current stats:
```bash
./bin/pangpstats
```

### Options
- `--update-geo`: Refreshes the IP prefix lists from `iserv.nl`.
- `--debug`: Prints the raw XML response from the firewall.

## Data Storage
Daily summaries are stored in the `data/` directory as JSON files (e.g., `2026-04-09.json`).
Prefix lists are cached in `data/geo/`.
