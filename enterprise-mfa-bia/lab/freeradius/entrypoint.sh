#!/bin/sh
# Injects the RADIUS shared secret at runtime so it is not baked into the image.
set -eu
: "${RADIUS_SHARED_SECRET:?RADIUS_SHARED_SECRET must be set}"
sed -i "s|__RADIUS_SHARED_SECRET__|${RADIUS_SHARED_SECRET}|g" /etc/freeradius/3.0/clients.conf
# -f foreground, -l stdout logging; set RADIUS_DEBUG=1 for full -X packet tracing.
if [ "${RADIUS_DEBUG:-0}" = "1" ]; then exec freeradius -X; fi
exec freeradius -f -l stdout
