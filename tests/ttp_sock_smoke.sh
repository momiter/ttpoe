#!/bin/sh
set -eu

usage() {
    cat <<'EOF'
usage:
  ./ttp_sock_smoke.sh normal-recv   <ifname> <vci> <peer-node>
  ./ttp_sock_smoke.sh trunc-recv    <ifname> <vci> <peer-node> <recv-len>
  ./ttp_sock_smoke.sh dontwait-recv <ifname> <vci> <peer-node> [recv-len]
  ./ttp_sock_smoke.sh send          <ifname> <vci> <peer-node> <message>

examples:
  ./ttp_sock_smoke.sh normal-recv vleth 0 00:00:02
  ./ttp_sock_smoke.sh trunc-recv  vleth 0 00:00:02 8
  ./ttp_sock_smoke.sh dontwait-recv vleth 0 00:00:02
  ./ttp_sock_smoke.sh send vleth 0 00:00:01 hello

notes:
  1. run 'make -C tests' first on a Linux host
  2. start the recv side before the send side
  3. verify late packets do not leak into /dev/noc_debug by clearing it before a
     socket session and checking it stays empty after the socket closes
EOF
}

if [ "$#" -lt 1 ]; then
    usage
    exit 2
fi

mode="$1"
shift

case "$mode" in
    normal-recv)
        exec ./ttp_sock_server "$@"
        ;;
    trunc-recv)
        exec ./ttp_sock_server "$@"
        ;;
    dontwait-recv)
        if [ "$#" -eq 3 ]; then
            exec ./ttp_sock_server "$1" "$2" "$3" 1023 --dontwait
        fi
        exec ./ttp_sock_server "$1" "$2" "$3" "$4" --dontwait
        ;;
    send)
        exec ./ttp_sock_client "$@"
        ;;
    *)
        usage
        exit 2
        ;;
esac
