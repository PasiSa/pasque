#!/bin/bash
#
# This script is used to create a couple of namespaces to test IP tunnels
# between the namespaces. Might be useful to someone.
# Works only on Linux.

set -euxo pipefail

# Cleanup
ip netns del ns1 || true
ip netns del ns2 || true
ip link del br0 || true
ip link del veth-ns1 || true
ip link del veth-ns2 || true

# Create namespaces
ip netns add ns1
ip netns add ns2

# Create veth pairs
ip link add veth-ns1 type veth peer name veth-ns1-br
ip link add veth-ns2 type veth peer name veth-ns2-br

# Move one end of each pair into namespace
ip link set veth-ns1 netns ns1
ip link set veth-ns2 netns ns2

# Create bridge
ip link add name br0 type bridge

# Connect bridge ends
ip link set veth-ns1-br master br0
ip link set veth-ns2-br master br0

# Bring up bridge and attached interfaces
ip link set br0 up
ip link set veth-ns1-br up
ip link set veth-ns2-br up

# Assign IPs inside namespaces
ip netns exec ns1 ip addr add 192.168.76.2/24 dev veth-ns1
ip netns exec ns1 ip link set veth-ns1 up
ip netns exec ns1 ip link set lo up

ip netns exec ns2 ip addr add 192.168.76.3/24 dev veth-ns2
ip netns exec ns2 ip link set veth-ns2 up
ip netns exec ns2 ip link set lo up

# Assign IP to bridge (root namespace)
ip addr add 192.168.76.1/24 dev br0
