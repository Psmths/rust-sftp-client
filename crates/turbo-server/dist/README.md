# rsftp-turbo (server)

UDP download accelerator for Rust SFTP Client. Browsing, authentication and
uploads keep using SSH/SFTP; downloads switch to rsftp-turbo automatically
when the server has it installed and UDP port 6767 is reachable. Otherwise
the client silently uses SFTP.

## Install (Linux, systemd)

```sh
tar xzf rsftp-turbo-<version>-linux-x86_64.tar.gz
cd rsftp-turbo
sudo ./install.sh
```

Then open UDP port 6767 in the server's firewall. The binary is statically
linked and runs on any x86_64 Linux distribution.

## How it works

1. The client runs `rsftp-turbo ticket` over its SSH connection and writes the
   file path to its stdin. That command runs as the logged-in user, so normal
   file permissions apply: it can only offer files that user can read.
2. It passes the open file to the daemon (`rsftp-turbo serve`) over the Unix
   socket `/run/rsftp-turbo/turbo.sock` and gets back a one-time transfer id and
   a random 256-bit key, which it prints for the client.
3. The client downloads the file over UDP in segments. Every packet is
   encrypted and authenticated with AES-256-GCM under that key; the daemon
   drops anything it cannot authenticate, answers only the IP address of the
   SSH session and rejects replayed requests.
4. For each segment the server first reports a SHA-256 digest; the client then
   requests the data in 1,200-byte chunks, re-requests lost ones and checks the
   segment against the digest, fetching it again on mismatch. If the file
   changes on the server during the download, the download fails instead of
   producing a mixed file.
5. Progress is kept in a hidden `.<name>.rsftp-part` file next to the
   destination: if turbo fails part-way, SFTP finishes only the missing pieces,
   and an interrupted download resumes where it stopped.

Transfers are forgotten (and their files closed) after 2 minutes without use.

The same SSH helper also lists directories for the client's file browser: a
line `{"list":"/some/dir"}` on its stdin is answered with the whole listing in
one JSON reply, read with the logged-in user's permissions. This needs neither
the daemon nor UDP.

## Running manually

```sh
rsftp-turbo serve --listen 0.0.0.0:6767 --socket /tmp/turbo.sock
echo /path/to/file | rsftp-turbo ticket --socket /tmp/turbo.sock
```

## Tuning for fast links

UDP bursts are absorbed by socket buffers. Both rsftp-turbo and the client ask
for 8 MiB buffers, but Linux caps them at `net.core.wmem_max` / `rmem_max`
(about 208 KiB by default). On fast or long-distance links, raise the caps on
the server and on Linux clients:

```sh
sudo sysctl -w net.core.rmem_max=8388608 net.core.wmem_max=8388608
# persist across reboots:
echo -e 'net.core.rmem_max=8388608\nnet.core.wmem_max=8388608' | sudo tee /etc/sysctl.d/90-rsftp-turbo.conf
```
