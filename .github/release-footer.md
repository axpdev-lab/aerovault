
## Install

### Linux (x86_64)

```bash
tar -xzf aerovault-x86_64-linux.tar.gz
sudo install -m 755 aerovault /usr/local/bin/aerovault
aerovault --help
```

### Windows (x86_64)

Extract `aerovault-x86_64-windows.zip` and run `aerovault.exe` from a terminal, or add its folder to your `PATH` to call `aerovault` from anywhere.

### From crates.io (Rust users)

```bash
cargo install aerovault-cli
```

Each archive ships a matching `.sha256` file; verify the download before running, e.g. `sha256sum -c aerovault-x86_64-linux.tar.gz.sha256`.
