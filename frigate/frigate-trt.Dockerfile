FROM ghcr.io/blakeblackshear/frigate:stable-tensorrt
RUN pip install --no-cache-dir --break-system-packages tensorrt==10.9.0.34 tensorrt-cu12==10.9.0.34 && echo "/usr/local/lib/python3.11/dist-packages/tensorrt_libs" > /etc/ld.so.conf.d/tensorrt.conf && ldconfig
