#!/bin/bash
#
# Copyright (C) 2022-2024 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#

set -e

cd "$(dirname "$0")"

# Start PTP
../../../../scripts/ptp.sh enp3s0
sleep 30

# Configure flow
./flow.sh enp3s0
sleep 30

# Start four instances of mirror applications
../../../../build/mirror -c mirror_vid100.yaml >mirror1.log &
sleep 1
../../../../build/mirror -c mirror_opcua_vid200.yaml >mirror2.log &
sleep 1
../../../../build/mirror -c mirror_opcua_vid300.yaml >mirror3.log &
sleep 1
../../../../build/mirror -c mirror_avtp_vid400.yaml >mirror4.log &

exit 0
