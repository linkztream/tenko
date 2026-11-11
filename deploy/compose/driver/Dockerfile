# The lab driver: the container from which a compose lab under deploy/compose is driven,
# attached to the lab's own networks (host.sh in this directory has the whole picture:
# what runs here, what stays on the host, and how the two talk). Every step that talks to
# a service of the lab runs here: the node's API (curl), the DNS questions (dig, delv,
# nsupdate), the certificates of the run (openssl), the DNSSEC keys and signatures (BIND's
# tools), the JSON handling (python3). The host only starts and stops containers.
#
# The base is the BIND release the DNS lab runs as its server, by digest, so that dig, delv
# and the signing tools are the server's own build; the other tools come from the
# distribution's packages (Alpine) at build time. Nothing is fetched when a lab runs.
FROM internetsystemsconsortium/bind9:9.20@sha256:66092edb53c081fa11b1fa8219e99065b0f497cb38f568ba789702a4c10e2590

# bash for the lab scripts; GNU coreutils, grep and sed for the options the scripts use
# (date +%s%3N, the BRE alternation of grep); curl for the API; openssl for the lab CA;
# python3 for the JSON of the API and the zone files.
RUN apk add --no-cache bash coreutils curl grep openssl python3 sed

# The lab's work volume is mounted here; the lab's scripts under /src (read-only).
WORKDIR /work
ENTRYPOINT ["sleep", "infinity"]
