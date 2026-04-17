#!/bin/sh
set -eu

usage() {
    cat <<'EOF'
usage:
  ./ttp_sock_smoke.sh normal-recv   <ifname> <vci> <peer-node>
  ./ttp_sock_smoke.sh trunc-recv    <ifname> <vci> <peer-node> <recv-len>
  ./ttp_sock_smoke.sh dontwait-recv <ifname> <vci> <peer-node> [recv-len]
  ./ttp_sock_smoke.sh send          <ifname> <vci> <peer-node>
  ./ttp_sock_smoke.sh send-exit     <ifname> <vci> <peer-node>
  ./ttp_sock_smoke.sh send-wait     <ifname> <vci> <peer-node> <linger-ms>

examples:
  ./ttp_sock_smoke.sh normal-recv vleth 0 00:00:02
  ./ttp_sock_smoke.sh trunc-recv  vleth 0 00:00:02 8
  ./ttp_sock_smoke.sh dontwait-recv vleth 0 00:00:02
  ./ttp_sock_smoke.sh send vleth 0 00:00:01
  ./ttp_sock_smoke.sh send-exit vleth 0 00:00:01
  ./ttp_sock_smoke.sh send-wait vleth 0 00:00:01 500

notes:
  1. run 'make -C tests' first on a Linux host
  2. place the file content to send in ./test.txt; one sendmsg sends one logical message
  3. the current single-message limit is 64KB
  4. start the recv side before the send side; received data is written to ./recv_test.txt
  5. verify late packets do not leak into /dev/noc_debug by clearing it before a
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
    send-exit)
        exec ./ttp_sock_client "$@"
        ;;
    send-wait)
        exec ./ttp_sock_client "$@"
        ;;
    *)
        usage
        exit 2
        ;;
esac
