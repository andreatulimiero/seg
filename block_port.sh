#!/bin/bash

info() {
  echo -e "[\x1b[33m*\x1b[0m] $1"
}

success() {
  echo -e "[\x1b[32m✓\x1b[0m] $1"
}

error() {
  echo -e "[\x1b[31mx\x1b[0m] $1"
}

ok_or_ko() {
  if [ $? -eq 1 ]; then
    error "$1"
    exit 1
  fi
}

print_usage() {
  echo "usage: $0 <block|unblock> <port_number>"
}

cmd_block() {
  info "Blocking port $1"
  sudo iptables -I INPUT -p udp --dport $1 -j DROP
}

cmd_unblock() {
  info "Unblocking port $1"
  sudo iptables -D INPUT -p udp --dport $1 -j DROP
}

if [ $# -ne 2 ]; then
  print_usage
  exit 1
fi

case $1 in 
  block | unblock)
    cmd_$1 $2
    ;;
  *)
    error "Possible command choices are 'block', 'unblock'"
    ;;
esac
success "Done"
