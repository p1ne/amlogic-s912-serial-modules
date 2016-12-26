#!/bin/sh
#

rm -f pl2303drv
/opt/gcc-linaro-aarch64-linux-gnu-4.9-2014.09_linux/bin/aarch64-linux-gnu-gcc -static find_dev.c libusbhost.c -o pl2303drv
/opt/gcc-linaro-aarch64-linux-gnu-4.9-2014.09_linux/bin/aarch64-linux-gnu-strip pl2303drv



