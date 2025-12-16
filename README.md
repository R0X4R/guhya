# **Guhya**

**Guhya** is a fast, multithreaded secret discovery tool built to uncover exposed keys, tokens, credentials, and other sensitive data from web resources and local files. It combines high-performance parallel fetching with a rich set of PCRE2 signatures to surface high-value leaks quickly and reliably.

> **In short:** feed Guhya URLs, files, or raw content → it scans using powerful regex signatures → deduplicates results → reports only real findings.



## ✨ Features

* ⚡ **High-performance scanning**
  Multithreaded workers for rapid analysis of large target sets.

* 🌐 **URL & file support**
  Scan HTTP/HTTPS endpoints, local files, or raw piped content.

* 🔍 **Rich detection engine**
  Dozens of curated PCRE2 patterns for API keys, OAuth tokens, cloud credentials, private keys, webhooks, and more.

* ➕ **Custom regex support**
  Add your own detection logic at runtime with `-p / --pattern`.

* 🧬 **De-duplication**
  Identical secrets are reported once—no noisy repeats.

* 🧭 **Detailed mode**
  Optional line-number reporting for faster remediation.

* 🎭 **User-Agent control**
  Use a custom UA or rotate from a large built-in pool.

* 🧱 **Portable & simple build**
  Pure C with `libcurl`, `PCRE2`, and `pthread`.



## 🚀 Why Guhya?

* **Fast by design** — parallel I/O + lightweight core
* **Low friction** — pipe-friendly, no config files needed
* **Extensible** — add patterns without recompiling
* **Practical** — built for real audits, not demos



## ⚠️ Responsible Use

Guhya is intended **only for authorized security testing** and internal audits.
Do not scan systems you do not own or explicitly have permission to test.
If you discover exposed secrets, follow responsible disclosure practices.



## 📦 Requirements

* Compiler: `gcc` (or compatible)
* Libraries:

  * `libcurl`
  * `libpcre2-8`
  * `pthread`

### Debian / Ubuntu

```sh
sudo apt update
sudo apt install build-essential libcurl4-openssl-dev libpcre2-dev make
```

### macOS (Homebrew)

```sh
brew install curl pcre2
```

### Windows

Use **MSYS2** or **MinGW** and install the corresponding `curl` and `pcre2` packages.



## 🔧 Build

```sh
make
```

This produces the `guhya` binary.

Linking:

```
-lcurl -lpcre2-8 -lpthread
```



## 🧪 Usage

Guhya reads input from **stdin**.
Each line can be:

* a URL (`http://` / `https://`)
* a local file path
* or raw content

### Basic Examples

```sh
cat urls.txt | guhya -t 50
```

```sh
guhya < config.json
```

```sh
echo "https://example.com" | guhya -d
```



## 🧰 Common Flags

```css
Guhya — A fast, multithreaded scanner that uncovers hidden secrets, keys, and tokens from web resources
Usage: guhya [flags]

FLAGS:
  -a, --user-agent      User-Agent string
  -c, --cookie          Cookie header to send
  -d, --detail          Detailed output (shows matching line numbers)
  -h, --help            Show this help
  -l, --label           Label to identify input source in output
  -o, --output          Output file to write results to
  -p, --pattern         Extra regex pattern to append
  -r, --random-agent    Enable random User-Agent to use
  -s, --silent          Silent (no banner)
  -t, --threads         Number of worker threads (default 50)
```

## 🧾 Advanced Examples

```sh
cat urls.txt | guhya -p "password\s*[:=]\s*['\"][^'\"]{8,}['\"]" -o secrets.out
```
```sh
cat urls.txt | guhya -t 100 -a "MyScanner/1.0"
```

```sh
git show HEAD:config.json | guhya -d -l config.json
```



## 🔬 How Detection Works

* Patterns are compiled using **PCRE2 (JIT enabled)** for speed
* URLs are fetched via **libcurl** with redirects enabled
* Local files are scanned directly
* All matches are **deduplicated in memory**
* Output is streamed immediately—no waiting for completion



## 🧩 Extending Guhya

* Use `-p` to add a single runtime pattern
* For permanent rules, add patterns to `patterns[]` and rebuild

## 🧪 Quick Tests

```sh
echo "AKIAEXAMPLEKEY12345678" | guhya
```
```sh
echo "password: supersecret123" | guhya -p "password\s*[:=]\s*[^\s]+"
```



## 🤝 Contributing

* PRs welcome for:

  * New patterns
  * Performance improvements
  * Bug fixes
* Keep regexes **specific** to reduce false positives


## 📄 License

This project is licensed under the **MIT License**.

You are free to use, copy, modify, merge, publish, distribute, sublicense, and sell copies of this software, provided that the original copyright notice and license text are included.

See the [LICENSE](LICENSE) file for full details.


## 🙏 Acknowledgements

Built with **libcurl** and **PCRE2** — fast, reliable, battle-tested.
