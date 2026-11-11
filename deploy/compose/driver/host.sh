# shellcheck shell=bash
# The host side of a compose lab (deploy/compose/lab-*): what remains on the host once the
# lab drives itself from inside its own network. A lab's entry script (smoke.sh) sources
# this file, builds its images, starts its driver container (the service `client`, or the
# one lab_driver names: the image of driver/Dockerfile, attached to the lab's networks) and
# calls lab_run with the lab's in-network script. That script runs in the driver: every API call, DNS
# question, certificate and JSON step happens there, against the containers' addresses.
#
# The host needs bash and Docker with the compose plugin, nothing else: no route to the
# lab's networks (Docker Desktop has none), no curl, python3 or openssl.
#
# Engine control stays on the host. The driver has no Docker socket (a container that
# controls the engine is root on the host). When the in-network script needs a container
# started, stopped or recreated, a network cut, a service's log or a setup token, it asks
# the host over its standard output (ctl in driver/ctl.sh), and lab_run answers on the
# driver's standard input. The host runs only the operations listed in lab_op, on the
# lab's own services, volumes and networks (lab_services, lab_volumes, lab_networks, set by
# the entry script), never a command line the driver wrote, except `exec` and `run` in the
# services the entry script lists in lab_exec_services.

# Git Bash: container paths in arguments stay as written; host paths go through host_path.
export MSYS_NO_PATHCONV=1

lab_services=()
lab_exec_services=()
lab_volumes=()
lab_networks=()
lab_summary=()

# host_path <path>: the path as Docker takes it (the Windows form under Git Bash).
host_path() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -m "$1"
  else
    printf '%s\n' "$1"
  fi
}

# lab_build_tree <repo>: the id of the checkout's build cache (deploy/Dockerfile says why
# each checkout has its own).
lab_build_tree() { (cd "$1" && pwd -P | sha256sum | cut -c1-16); }

# lab_image <variable> <default tag> <dockerfile> <context> [build arguments...]: builds the
# image unless the variable names one; exports the variable with the tag either way.
lab_image() {
  local variable="$1" tag="$2" dockerfile="$3" context="$4"
  shift 4
  if [[ -n "${!variable:-}" ]]; then
    docker image inspect "${!variable}" >/dev/null 2>&1 || {
      printf 'lab: image %s (%s) not found\n' "${!variable}" "$variable" >&2
      return 1
    }
    printf '\n==> use the existing image %s\n' "${!variable}"
  else
    printf '\n==> build the image %s\n' "$tag"
    docker build -f "$(host_path "$dockerfile")" "$@" -t "$tag" "$(host_path "$context")"
    printf -v "$variable" '%s' "$tag"
  fi
  # shellcheck disable=SC2163 # the variable's name is the argument
  export "$variable"
}

# lab_driver_image <repo>: the driver's image (DRIVER_IMAGE, default tenko-lab-driver:local).
# The labs mount parts of their volume (compose `volume.subpath`), which needs Docker Engine
# 26 (API 1.45) or later: an older engine is named here rather than in a compose error.
lab_driver_image() {
  local api major minor
  api="$(docker version -f '{{.Server.APIVersion}}' 2>/dev/null || true)"
  major="${api%%.*}"
  minor="${api#*.}"
  if ! [[ "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ ]] || ((major == 1 && minor < 45)); then
    printf 'lab: Docker Engine 26 or later is needed (API 1.45); this engine has API %s\n' \
      "${api:-unknown}" >&2
    return 1
  fi
  lab_image DRIVER_IMAGE tenko-lab-driver:local "$1/deploy/compose/driver/Dockerfile" \
    "$1/deploy/compose/driver"
}

lab_member() {
  local item="$1"
  shift
  local candidate
  for candidate in "$@"; do
    [[ "$candidate" == "$item" ]] && return 0
  done
  return 1
}
lab_service() {
  lab_member "$1" "${lab_services[@]}" || {
    printf 'lab: %s is not a service of the lab\n' "$1" >&2
    return 2
  }
}
lab_volume() {
  lab_member "$1" "${lab_volumes[@]}" || {
    printf 'lab: %s is not a volume of the lab\n' "$1" >&2
    return 2
  }
}
lab_network() {
  lab_member "$1" "${lab_networks[@]}" || {
    printf 'lab: %s is not a network of the lab\n' "$1" >&2
    return 2
  }
}
lab_container() { compose ps -a -q "$1"; }
# lab_project_name: the compose project the operations act on (an entry script with a
# project per round redefines it).
lab_project_name() { printf '%s\n' "$COMPOSE_PROJECT_NAME"; }

# lab_op <operation> <arguments...>: one engine operation the driver asked for. Its standard
# output is the answer the driver reads; compose's own messages go to the host's log.
lab_op() {
  local op="$1" service
  shift
  case "$op" in
    up)
      # Named services only: `up` without one would start the whole project.
      (($# > 0)) || return 2
      for service in "$@"; do lab_service "$service" || return; done
      compose up -d --no-build "$@" >&2
      ;;
    recreate)
      lab_service "$1" || return
      compose up -d --no-build --force-recreate "$1" >&2
      ;;
    restart | stop | start)
      lab_service "$1" || return
      compose "$op" "$1" >&2
      ;;
    healthy)
      lab_service "$1" || return
      [[ "$(docker inspect -f '{{.State.Health.Status}}' "$(lab_container "$1")" 2>/dev/null)" == healthy ]]
      ;;
    logs)
      lab_service "$1" || return
      compose logs --no-color --no-log-prefix "$1" 2>&1
      ;;
    disconnect)
      lab_service "$1" && lab_network "$2" || return
      docker network disconnect "$(lab_project_name)_$2" "$(lab_container "$1")" >&2
      ;;
    connect)
      # connect <service> <network> [<address>]: the service back on the network under its
      # name, at its fixed address when given.
      lab_service "$1" && lab_network "$2" || return
      local -a fixed=()
      if [[ -n "${3:-}" ]]; then
        [[ "$3" =~ ^[0-9a-f.:]+$ ]] || return 2
        fixed=(--ip "$3")
      fi
      docker network connect --alias "$1" "${fixed[@]}" "$(lab_project_name)_$2" "$(lab_container "$1")" >&2
      ;;
    setup-token)
      lab_service "$1" || return
      compose exec -T "$1" /usr/local/bin/tenko setup token --data-dir /var/lib/tenko
      ;;
    fresh)
      # fresh <service> <volume>: the container and its data volume removed, so that the
      # service starts as a new installation.
      lab_service "$1" && lab_volume "$2" || return
      compose rm -sf "$1" >&2 || true
      docker volume rm "$(lab_project_name)_$2" >/dev/null 2>&1 || true
      ;;
    copy-volume)
      # copy-volume <from> <to>: a copy of a data volume, through the driver's image.
      lab_volume "$1" && lab_volume "$2" || return
      docker volume create "$(lab_project_name)_$2" >/dev/null &&
        docker run --rm --network none --entrypoint sh \
          -v "$(lab_project_name)_$1:/from" -v "$(lab_project_name)_$2:/to" \
          "$DRIVER_IMAGE" -c 'rm -rf /to/* && cp -a /from/. /to/'
      ;;
    volume-rm)
      lab_volume "$1" || return
      docker volume rm "$(lab_project_name)_$1" >/dev/null 2>&1 || true
      ;;
    exec | run)
      # exec <service> [-e NAME=VALUE]... [--stdin TEXT] [--merge] [--] <command...>: a
      # command in a running service the lab lists in lab_exec_services; with --stdin, TEXT
      # and a line break are its standard input; with --merge its standard error is part of
      # the answer (else it goes to the host's log). run: the same in a new container of the
      # service (compose run --rm --no-deps --use-aliases, the command's first word the
      # entrypoint).
      lab_member "$1" "${lab_exec_services[@]}" || {
        printf 'lab: no %s in %s\n' "$op" "$1" >&2
        return 2
      }
      service="$1"
      shift
      local -a options=()
      local input="" has_input=0 merge=0
      while (($# > 0)); do
        case "$1" in
          -e)
            [[ "${2:-}" =~ ^[A-Z_][A-Z0-9_]*= ]] || return 2
            options+=(-e "$2")
            shift 2
            ;;
          --stdin)
            (($# >= 2)) || return 2
            input="$2"
            has_input=1
            shift 2
            ;;
          --merge)
            merge=1
            shift
            ;;
          --)
            shift
            break
            ;;
          *) break ;;
        esac
      done
      (($# > 0)) || return 2
      if [[ "$op" == run ]]; then
        options+=(--rm --no-deps --use-aliases --entrypoint "$1")
        shift
      fi
      if ((has_input && merge)); then
        printf '%s\n' "$input" | compose "$op" -T "${options[@]}" "$service" "$@" 2>&1
      elif ((has_input)); then
        printf '%s\n' "$input" | compose "$op" -T "${options[@]}" "$service" "$@"
      elif ((merge)); then
        compose "$op" -T "${options[@]}" "$service" "$@" 2>&1
      else
        compose "$op" -T "${options[@]}" "$service" "$@"
      fi
      ;;
    kill)
      lab_service "$1" || return
      compose kill "$1" >&2
      ;;
    *)
      # An operation of the lab's own (lab_extra_op, defined by the entry script).
      if declare -F lab_extra_op >/dev/null; then
        lab_extra_op "$op" "$@"
        return
      fi
      printf 'lab: unknown operation %s\n' "$op" >&2
      return 2
      ;;
  esac
}

# lab_run <script in the driver> [docker compose exec options...]: runs the lab's
# in-network script in the driver (the service lab_driver names, default `client`) and
# serves its requests until it ends; returns its exit status. The lines it prints pass
# through to the host's standard output; its summary lines are kept in lab_summary for the
# entry script to print last, and a count of failed rows it reports in lab_rows_failed.
lab_rows_failed=0
lab_run() {
  local script="$1" line status=0 pid from to request out
  shift
  # The channel's marker: 128 random bits, so that nothing the lab's services print (their
  # logs and API answers pass through the channel) can pose as a request.
  local rpc
  rpc="@@lab-rpc-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
  local -a argv
  coproc LAB_DRIVER {
    compose exec -T -e "LAB_RPC=$rpc" "$@" "${lab_driver:-client}" bash "$script"
  }
  pid="$LAB_DRIVER_PID"
  # bash unsets the coprocess's variables when it ends; these copies keep its last lines.
  exec {from}<&"${LAB_DRIVER[0]}" {to}>&"${LAB_DRIVER[1]}"
  trap '' PIPE
  # A request is a line of its own that starts with the marker (a trace of the driver's shell,
  # set -x, shows the marker inside a line: that is output).
  while IFS= read -r line <&"$from" || [[ -n "$line" ]]; do
    case "$line" in
      "$rpc summary "*) lab_summary+=("${line#"$rpc summary "}") ;;
      "$rpc rows-failed "*) lab_rows_failed=$((lab_rows_failed + ${line##* })) ;;
      "$rpc "*)
        request="${line#"$rpc "}"
        # The trailing separator keeps a last argument that is empty.
        IFS=$'\x1f' read -r -a argv <<<"$request"$'\x1f'
        out="$(lab_op "${argv[@]}" </dev/null)" && status=0 || status=$?
        {
          [[ -z "$out" ]] || printf '%s\n' "$out"
          printf '%s end %s\n' "$rpc" "$status"
        } >&"$to" || true
        ;;
      *) printf '%s\n' "$line" ;;
    esac
  done
  trap - PIPE
  exec {from}<&- {to}>&-
  wait "$pid" && status=0 || status=$?
  return "$status"
}

# lab_print_summary: the summary lines of the in-network script, after the logs.
lab_print_summary() {
  if ((${#lab_summary[@]} > 0)); then
    printf '\n==> summary\n'
    printf '%s\n' "${lab_summary[@]}"
  fi
}
