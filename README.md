# Guhya

Guhya is a fast, multithreaded scanner designed to discover exposed secrets, keys, tokens, and other sensitive data in web resources and local files. It combines efficient parallel fetching with a comprehensive set of PCRE2-based signatures to quickly surface high-value findings.

**Quick summary:** Scans stdin content, local files, or URLs (queued via stdin), matches them against many built-in regex patterns (and optional custom patterns), and reports unique discoveries to stdout or an output file.

**Features**
- **Multithreaded scanning:** Configurable worker threads for high throughput.
- **Content & URL modes:** Accepts raw content or a list of URLs / file paths via stdin.
- **Comprehensive patterns:** Dozens of PCRE2 signatures for API keys, tokens, private keys, webhook URLs, cloud credentials, and more.
- **Custom patterns:** Append your own regex with `-p`/`--pattern`.
- **Flexible output:** Print to stdout and/or write to a file with `-o`/`--output`.
- **User-Agent control:** Set a specific UA or enable randomized UAs for requests.
- **Detailed reporting:** Optional detailed output including discovered line numbers.

**Benefits**
- **Fast discovery:** Parallel workers and libcurl-backed fetches speed up scanning large target lists.
- **Low false-positive friction:** De-duplication of identical secrets across inputs.
- **Extensible:** Add or extend regexes at runtime with the `--pattern` flag.
- **Portable build:** Simple Makefile using `gcc`, `libcurl`, `libpcre2`, and pthreads.

**Responsible use notice**
Guhya is a security tool intended for authorized security testing, discovery, and remediation. Do not scan systems you do not own or have explicit written permission to test. Follow responsible disclosure practices for any secrets exposed.

**Requirements**
- POSIX-compatible build tools (`gcc`, `make`) or an appropriate toolchain on Windows (MSYS2 / MinGW).
- Libraries: `libcurl`, `libpcre2-8`, `pthread` (on Linux/macOS these are typically available via your package manager).

On Debian/Ubuntu you can install prerequisites with:

```sh
sudo apt update
sudo apt install build-essential libcurl4-openssl-dev libpcre2-dev make
```

On macOS (with Homebrew):

```sh
brew install curl pcre2
```

On Windows, use MSYS2 or a compatible MinGW environment and install the corresponding `curl` and `pcre2` packages.

**Build**
The repository contains a simple Makefile. From the project root run:

```sh
make
```

This produces the `guhya` binary. The Makefile compiles `src/main.c`, `src/scanner.c`, and `src/network.c` and links against `-lcurl -lpcre2-8 -lpthread`.

**Usage**
Guhya reads either raw content or newline-delimited targets from `stdin`. Targets can be URLs (http/https) or local file paths.

Basic usage:

```sh
# Scan a list of URLs in urls.txt
cat urls.txt | ./guhya -t 50 -o findings.txt

# Scan a single file's content
./guhya < somefile.txt

# Scan a single URL
echo "https://example.com" | ./guhya -d
```

Common flags:
- **-a, --user-agent**: Set a custom User-Agent string.
- **-r, --random-agent**: Enable random selection from bundled User-Agents.
- **-c, --cookie**: Send a cookie header with requests.
- **-d, --detail**: Enable detailed output (includes matched line numbers and pattern names).
- **-t, --threads**: Number of worker threads (default: 50).
- **-p, --pattern**: Add an extra PCRE2 regex to run alongside built-in patterns.
- **-o, --output**: Write findings to the specified file.
- **-l, --label**: Set the input label used when scanning content from stdin (default: "stdin").
- **-s, --silent**: Suppress the banner and informational logs.
- **-h, --help**: Show help text.

Examples:

```sh
# Add a custom regex and write to file
cat urls.txt | ./guhya -p "password\s*[:=]\s*['\"][^'\"]{8,}['\"]" -o secrets.out

# Use a specific User-Agent and 100 threads
cat urls.txt | ./guhya -a "MyScanner/1.0" -t 100

# Scan raw content piped from a tool
git show HEAD:config.json | ./guhya -d -l config.json
```

**How detection works (brief)**
- Built-in patterns are compiled using PCRE2 with JIT enabled for performance.
- The scanner de-duplicates identical secrets using an in-memory list to avoid repeated reporting.
- When given a URL, `libcurl` fetches contents with follow-location and a configurable timeout; local files are read directly.

**Extending & Custom Patterns**
You can append one additional pattern at runtime using the `-p` flag. For more advanced use (multiple custom rules), consider modifying `src/scanner.c` to include your patterns in the `patterns[]` table and rebuild.

**Development notes**
- Source files: [src/main.c](src/main.c), [src/network.c](src/network.c), [src/scanner.c](src/scanner.c)
- Header: [include/guhya.h](include/guhya.h)
- Build: [Makefile](Makefile)

**Testing**
Quick manual test ideas:

```sh
echo "AKIAEXAMPLEKEY12345678" | ./guhya -d
echo "username: password1234" | ./guhya -p "password\s*[:=]\s*[^\s]+" -d
```

**Contributing**
- Fork, implement fixes or patterns, and open a PR. Include tests or example inputs if adding patterns.
- When adding new patterns, ensure they are reasonably specific to limit false positives.

**License**
No license is included in this repository. If you intend to publish or share this project, add a `LICENSE` file (for example, MIT) to make the terms explicit.

**Contact & Support**
Open issues on the repository for bug reports, feature requests, or to discuss pattern improvements.

**Acknowledgements**
Built with `libcurl` and `PCRE2` for efficient network fetches and regex scanning.

