# NixOS module for bktunnel — the declarative equivalent of the systemd
# template unit in packaging/systemd/. Declare one entry per tunnel under
# services.bktunnel.instances.<name>; each becomes its own hardened
# systemd service (bktunnel-<name>).
#
# Consumed via the flake's nixosModules.bktunnel output, which sets
# services.bktunnel.package to the flake's build. Example (configuration.nix):
#
#   imports = [ bktunnel.nixosModules.bktunnel ];
#   services.bktunnel.instances.mqtt = {
#     role = "client";
#     accept = "127.0.0.1:1883";
#     connect = "server.example:5560";
#     privateKeyFile = "/etc/bktunnel/mqtt.key";   # 0600; see note below
#     peers = [ "wwy/Nwo5y+eUPl7P+dv5CjT9fybiarNipZ+q+NZNsZg=" ];
#   };
{ config, lib, pkgs, ... }:

let
  cfg = config.services.bktunnel;

  instanceModule = { name, ... }: {
    options = {
      role = lib.mkOption {
        type = lib.types.enum [ "client" "server" ];
        description = "Tunnel role: client (plaintext in, TLS out) or server (TLS in, plaintext out).";
      };
      accept = lib.mkOption {
        type = lib.types.str;
        example = "127.0.0.1:1883";
        description = "address:port to listen on (bktunnel -a).";
      };
      connect = lib.mkOption {
        type = lib.types.str;
        example = "server.example:5560";
        description = "address:port to forward to (bktunnel -c).";
      };
      peers = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [ "wwy/Nwo5y+eUPl7P+dv5CjT9fybiarNipZ+q+NZNsZg=" ];
        description = "Pinned peer public keys, base64 (bktunnel -p). Use this or peersFile.";
      };
      peersFile = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Absolute path to a file of pinned peer pubkeys, one per line (bktunnel -p @FILE). Alternative to peers.";
      };
      privateKeyFile = lib.mkOption {
        type = lib.types.str;
        example = "/etc/bktunnel/mqtt.key";
        description = ''
          Absolute path to this host's private key file (mode 0600). It is
          loaded into the service via systemd LoadCredential=, so it never
          appears on the command line or in the environment. Point it at a
          secret from agenix/sops-nix or a manually-placed file — do NOT inline
          the key (a Nix string/path would land world-readable in the store).
        '';
      };
    };
  };

  mkService = name: inst: lib.nameValuePair "bktunnel-${name}" {
    description = "bktunnel pinned-identity TLS tunnel (${name})";
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      # $CREDENTIALS_DIRECTORY is set by systemd because of LoadCredential=
      # below; the \${...} is escaped so Nix leaves it for systemd to expand.
      ExecStart = "${cfg.package}/bin/bktunnel -r ${inst.role} -a ${inst.accept} -c ${inst.connect} "
        + "-k @\${CREDENTIALS_DIRECTORY}/privkey "
        + (if inst.peersFile != null
           then "-p @${inst.peersFile}"
           else lib.concatMapStringsSep " " (p: "-p ${p}") inst.peers);
      LoadCredential = "privkey:${inst.privateKeyFile}";
      Restart = "on-failure";
      RestartSec = 2;

      # Hardening — mirrors packaging/systemd/bktunnel@.service.
      DynamicUser = true;
      NoNewPrivileges = true;
      ProtectSystem = "strict";
      ProtectHome = true;
      PrivateTmp = true; # also a private, writable /dev/shm for the bash impl
      PrivateDevices = true;
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      ProtectKernelLogs = true;
      ProtectControlGroups = true;
      ProtectClock = true;
      ProtectHostname = true;
      RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
      RestrictNamespaces = true;
      RestrictRealtime = true;
      RestrictSUIDSGID = true;
      LockPersonality = true;
      MemoryDenyWriteExecute = true;
      SystemCallFilter = [ "@system-service" ];
      SystemCallErrorNumber = "EPERM";
      SystemCallArchitectures = "native";
      # No capabilities needed for high ports; for a port <1024 set
      # AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ]; instead of the empty set.
      CapabilityBoundingSet = "";
      UMask = "0077";
    };
  };
in
{
  options.services.bktunnel = {
    package = lib.mkOption {
      type = lib.types.package;
      description = "The bktunnel package providing bin/bktunnel.";
    };
    instances = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule instanceModule);
      default = { };
      description = "bktunnel tunnel instances; each becomes one systemd service.";
    };
  };

  config = lib.mkIf (cfg.instances != { }) {
    assertions = lib.mapAttrsToList (name: inst: {
      assertion = inst.peers != [ ] || inst.peersFile != null;
      message = "services.bktunnel.instances.${name}: set at least one peer via `peers` or `peersFile`.";
    }) cfg.instances;

    systemd.services = lib.mapAttrs' mkService cfg.instances;
  };
}
