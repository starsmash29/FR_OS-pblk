"""Light-weight IoT device discovery and isolation (phase 14).

- frfw.iot.leases   -- active DHCP leases from Kea's lease file (root, via the helper)
- frfw.iot.arp      -- the kernel's neighbour table (unprivileged)
- frfw.iot.mdns     -- one-shot mDNS/DNS-SD service discovery (unprivileged)
- frfw.iot.oui      -- MAC vendor lookup against the IEEE registry
- frfw.iot.classify -- transparent point-based "is this IoT?" scoring
- frfw.iot.scanner  -- ties it together; `fr-iot-scan` entry point

Enforcement (the kernel `iot_isolated` MAC set) lives in
frfw.iot_isolation, reached only through the privileged apply-helper.
"""
