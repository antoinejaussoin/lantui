# lantui

A terminal UI for scanning the local network. It lists machines on the LAN
with IPv4/IPv6, MAC, hostname, ping, vendor, DNS, mDNS, and SMB names.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/antoinejaussoin/lantui/main/install.sh | sh
```

That downloads the matching Mac or Linux binary from GitHub Releases into
`~/.local/bin`. Override with `LANTUI_BINDIR`, `LANTUI_VERSION`
(`latest`, `nightly`, or a tag like `v0.1.0`), or `LANTUI_REPO`.

From source:

```bash
cargo install --path .
```

## Cross-build

From macOS, with [rustup](https://rustup.rs/) and [zig](https://ziglang.org/) (`brew install zig`):

```bash
make
```

That writes three release binaries to `dist/`:

| File | Target |
| --- | --- |
| `lantui-macos-arm64` | Apple Silicon |
| `lantui-linux-x64` | Linux x86_64 (glibc 2.17+) |
| `lantui-linux-arm64` | Linux aarch64 (glibc 2.17+) |

Linux hosts skip the Mac target: `make linux`. Individual targets: `make macos`, `make linux-x64`, `make linux-arm64`.

## Usage

```bash
# Interactive table. ARP needs root on macOS and Linux.
sudo lantui

# Unprivileged fallback: ping + neighbor cache + mDNS/SSDP.
lantui

# Live rescan every 15 seconds
sudo lantui --live --interval 15

# Pick an interface or CIDR
sudo lantui --iface en0
sudo lantui --range 192.168.1.0/24

# One-shot output
sudo lantui scan
sudo lantui scan --json
sudo lantui scan --csv
```

Without sudo, lantui still runs. The status bar says so: quiet hosts that
do not answer ping or advertise mDNS/SSDP may be missing.

On recent macOS, grant Local Network access to your terminal (or run with
`sudo`). Unsigned processes otherwise see a placeholder MAC and an empty
ARP table, so vendor columns stay blank until an ARP sweep can run.

`NO_COLOR` or `--no-color` turns colour off.

## Keys

| Key | Action |
| --- | --- |
| `j` / `k` | Move |
| `/` | Filter |
| `c` | Show, hide, and reorder columns (narrow terminals hide extras first) |
| `s` / `S` | Sort column / direction |
| `l` | Live mode |
| `r` | Rescan |
| `o` | Hide offline hosts |
| `p` | Probe common ports on the selected host |
| `n` | Comment |
| `e` | Export CSV |
| `y` / `Y` | Copy IPv4 / MAC |
| `i` | Interface picker |
| `?` | Help |
| `q` | Quit |

Column layout, sort, and comments are saved under the platform config
directory (`~/Library/Application Support/lantui` on macOS).

## How it scans

1. Picks the default-route interface (skips loopback and point-to-point).
2. If a raw/BPF socket opens, broadcasts ARP to every host in the scan range.
3. Otherwise pings the range and reads the neighbor cache (`arp`/`ndp` on
   macOS, `/proc/net/arp` and `ip neigh` on Linux).
4. Collects IPv6 from NDP and mDNS AAAA records. A /64 is never swept.
5. Resolves mDNS, unicast DNS PTR, NetBIOS/SMB, and SSDP.
6. Looks up the MAC vendor in a bundled IEEE OUI snapshot.

Prefixes shorter than /22 scan the /24 that contains the local address,
unless `--range` is set. /31 and /32 are skipped.
