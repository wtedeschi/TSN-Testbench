# TSN Linux Testbench #

## About ##

TSN-``Testbench`` is a real time traffic simulation. PROFINET as well as OPC/UA
PubSub and other configurable protocols are supported. The evaluation
application is used to simulate a PLC. It generates RT and non-RT traffic,
mirrors traffic and performs consistency checks. The evaluation is split into
two applications:

- ``reference``: Traffic generation and checking simulation
- ``mirror``: Traffic mirror application

The concept is shown below.

<img src="Documentation/images/overview.png" width="600" alt="TSN-Testbench" />

### Motivation ###

Over the last years the Linux kernel and open source ecosystem in general
introduced TSN functionalities. This includes the time synchronization with PTP
via 802.1AS, various traffic shapers defined by IEEE and deterministic frame
reception and transmission. Furthermore, the PREEMPT_RT patch turns Linux into
an Real Time Operating System. How well do these mechanisms perform for real
world use cases? For instance, is it possible to run PROFINET over TSN on top of
Linux?

In order to answer these questions, the TSN-``Testbench`` has been
developed. The purpose of that tool is to evaluate manufacturer’s hardware as
well as underlying drivers and Linux network stack itself. Thereby, please note
that is not a TSN conformance testing tool, but rather intended for
evaluation. The tool itself is independent of hardware manufactures TSN
solutions by utilizing only Linux mainline utilities for data and control plane.

While the development of the tool started for PROFINET RT and later TSN, it is
now able to generate any kind of cyclic Ethernet payload. This way, different
``middlewares`` next to PROFINET such as OPC/UA can be simulated and tested.

The overall idea is shown below.

<img src="Documentation/images/multimiddleware.png" width="400" alt="Multi Middleware" />

### Architecture ###

The application itself performs cyclic Ethernet communication. There are
different traffic classes ranging from real time Layer 2 up to UDP
communication. The cyclic receivers and transmitters utilize either traditional
``AF_PACKET`` or modern ``AF_XDP`` sockets. For both socket types the receive
flow is configured via either BPF filters or eBPF XDP programs. Based on the
configuration, or profiles, the TSN-``Testbench`` can simulate different traffic
types such as PROFINET or OPC/UA PubSub. The image below shows an example of
three different middlewares in combination with non-real time applications
utilizing XDP.

<img src="Documentation/images/ref_test_app_architecture_xdp.png" width="600" alt="TSN-Testbench XDP Architecture" />

## Documentation ##

The documentation includes information on how to build, use and run the
TSN-``Testbench``.  The documentation build requires ``sphinx``. To generate the
HTML form use:

    $ cd Documentation
    $ make html
    $ firefox _build/html/index.html

## Credits ##

Design and funding by Phoenix Contact Electronics GmbH

## Copyright ##

Copyright (C) 2020-2023 Linutronix GmbH

## License ##

BSD-2 Clause and Dual BSD/GPL for all eBPF programs
