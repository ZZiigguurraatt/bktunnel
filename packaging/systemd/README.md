# systemd integration

The `.deb` installs the template unit to `/usr/lib/systemd/system/` and the
config samples under `/usr/share/doc/bktunnel/examples/`. From a source
checkout, install them yourself as shown below.

## `bktunnel@.service` — systemd template unit

Runs one bktunnel tunnel per instance. An instance `foo` reads three files under
`/etc/bktunnel/`:

| File | What | Perms |
|------|------|-------|
| `foo.conf` | `ROLE` / `ACCEPT` / `CONNECT` (an `EnvironmentFile`) | `0644` |
| `foo.key` | this host's **private** key | `0600`, root |
| `foo.peers` | pinned **peer** public keys, one per line | `0644` |

The unit loads `foo.key` via systemd's `LoadCredential=` into a per-service
tmpfs, so the private key is never on the command line (`ps`) or in the
environment (`/proc/PID/environ`). It works with either implementation at
`/usr/bin/bktunnel` (the bash script or the Go binary).

### Setup

```sh
# 1. install bktunnel itself (bash script, `make install-system`, or the .deb)
#    so /usr/bin/bktunnel exists. The .deb already installs the unit; from a
#    source checkout install it yourself:
sudo install -m 0644 packaging/systemd/bktunnel@.service /etc/systemd/system/
sudo systemctl daemon-reload

# 2. per-instance config + keys (instance name "mqtt" here)
sudo mkdir -p /etc/bktunnel
sudo bktunnel -g /etc/bktunnel/mqtt.key          # writes mqtt.key (0600) + mqtt.key.pub
sudo install -m 0644 packaging/systemd/bktunnel.conf.example  /etc/bktunnel/mqtt.conf
sudo install -m 0644 packaging/systemd/bktunnel.peers.example /etc/bktunnel/mqtt.peers
sudoedit /etc/bktunnel/mqtt.conf                 # set ROLE/ACCEPT/CONNECT
sudoedit /etc/bktunnel/mqtt.peers               # put the PEER's pubkey here

# 3. exchange public keys: give the peer your mqtt.key.pub line, and put the
#    peer's pubkey in mqtt.peers. (Recover your pubkey any time with:
#      sudo bktunnel -k @/etc/bktunnel/mqtt.key -P )

# 4. start it
sudo systemctl enable --now bktunnel@mqtt
systemctl status bktunnel@mqtt
journalctl -u bktunnel@mqtt -f
```

### Notes

- **Privileged ports.** The examples bind high ports (`:5560`, `:1883`), which
  need no capabilities. To bind a port `<1024`, drop the empty
  `CapabilityBoundingSet=` line and add `AmbientCapabilities=CAP_NET_BIND_SERVICE`.
- **Hardening.** The sandboxing directives are a starting point; if a component
  trips one, relax that specific directive. `PrivateTmp=yes` deliberately
  provides the private, writable `/dev/shm` the bash implementation uses for its
  ephemeral key material.
- **Older systemd (< 247, no `LoadCredential=`).** Replace `DynamicUser=yes`
  with a fixed `User=bktunnel` (create it), drop the `LoadCredential=` line,
  `chown bktunnel /etc/bktunnel/foo.key`, and change `-k @${CREDENTIALS_DIRECTORY}/privkey`
  to `-k @/etc/bktunnel/foo.key`.
- **Stopping.** `systemctl stop bktunnel@mqtt` sends `SIGTERM`; bktunnel shreds
  and removes its RAM key material and tears down the tunnel on the way out.
