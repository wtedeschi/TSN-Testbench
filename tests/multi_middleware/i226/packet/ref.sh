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

# Start four instances of reference applications
../../../../build/reference -c reference_vid100.yaml >ref1.log &
sleep 1
../../../../build/reference -c reference_opcua_vid200.yaml >ref2.log &
sleep 1
../../../../build/reference -c reference_opcua_vid300.yaml >ref3.log &
sleep 1
../../../../build/reference -c reference_avtp_vid400.yaml >ref4.log &

exit 0
