# Pinned to the release currently running (API reports 0.18.0-77a66e7). The digest is
# the exact base the running image was built from, so a rebuild cannot upgrade Frigate
# (and its database schema) by surprise. Bump tag and digest together, on purpose.
FROM ghcr.io/blakeblackshear/frigate:0.18.0-tensorrt@sha256:82d7475ba7e5f950911bd9d06f2392de96881f39eeacd78824a526dde9b5cad9
RUN pip install --no-cache-dir --break-system-packages tensorrt==10.9.0.34 tensorrt-cu12==10.9.0.34 && echo "/usr/local/lib/python3.11/dist-packages/tensorrt_libs" > /etc/ld.so.conf.d/tensorrt.conf && ldconfig
