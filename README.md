# Byse Resolver

A Python CLI that takes a Byse embed URL and prints the final, temporary HLS URL. It handles player identification, access attestation, proof of work, and playback decryption without launching a browser or executing the JavaScript player.

## Installation

Requires Python 3.10+ and a C compiler. The **Cython proof-of-work extension is required** and is compiled during installation. On Linux, install your distribution's C build tools and Python development headers; on macOS, install the Xcode Command Line Tools; on Windows, install MSVC Build Tools with C++ support.

From the cloned repository:

```sh
python -m venv .venv
source .venv/bin/activate
python -m pip install .
```

On Windows, activate the environment with `.venv\Scripts\activate`.

## Usage

```sh
byse-resolver 'https://host.example/e/video-code'
```

Successful output is one URL followed by a newline:

```text
https://media.example/master.m3u8?token=temporary
```

The host above is a placeholder. Supply a real Byse embed URL. Optional title slugs after the video code are supported. Domain aliases are identified by the player's HTML title.

If the video restricts which page may embed it, pass that page's URL:

```sh
byse-resolver 'https://host.example/e/video-code' \
  --referer 'https://site.example/watch/video'
```

You can also run `python -m byse_resolver`. Use `--help` for options and `--version` for the installed version.

Only the resolved URL goes to stdout, making it suitable for scripts and pipes. Errors go to stderr. Exit status is `0` on success, `1` for resolution failures or unavailable streams, `2` for invalid CLI arguments, and `130` on interruption. If multiple HLS sources are available, the resolver selects the highest reported height, preserving provider order for ties. It does not download or probe the media.

## Why Cython?

The proof-of-work challenge repeatedly evaluates a custom hash with 32-bit arithmetic, rotations, and indexed scratch memory. Running this computationally intensive loop through Python objects adds interpreter overhead for every candidate.

**Cython compiles the hot loop to native code**, using `uint32_t` arithmetic, C arrays, and native buffers. The inner loop creates no Python objects and runs with the GIL released, allowing other Python threads to progress. Releasing the GIL does not itself make the calculation faster or distribute it across CPU cores: the optimization comes from native arithmetic and memory access.

Python handles HTTP, protocol orchestration, and cryptography through `requests` and `cryptography`. Only the proof-of-work kernel is implemented in Cython. Searches run in batches of 2,048 candidates, with a deadline checked between batches. The default proof-of-work budget is 120 seconds; each HTTP request has a 15-second timeout. These are separate limits, not an overall CLI deadline.

The tradeoff is a native build requirement and platform-specific compiled artifacts. No speedup ratio is claimed without a reproducible benchmark. Fixed digest vectors and a known challenge solution verify the native implementation's behavior.

## Development

```sh
python -m pip install -e .
python -W error::ResourceWarning -m unittest discover -s tests -v
```

Tests use mocked HTTP responses and local cryptographic fixtures, with no requests to external video hosts. After changing the `.pyx` file, reinstall to rebuild the extension.

## Usage notice

Use only with content you are authorized to access. Resolved URLs are temporary and may be bound to the requesting IP or session. Changes to the upstream player or protocol can require resolver updates.
