export V?=0

# If _HOST or _TA specific compilers are not specified, then use CROSS_COMPILE
# Only for host application. Shadow-box TA is included in OP-TEE OS
HOST_CROSS_COMPILE ?= $(CROSS_COMPILE)

.PHONY: all
all:
	$(MAKE) -C host CROSS_COMPILE="$(HOST_CROSS_COMPILE)"

.PHONY: clean
clean:
	$(MAKE) -C host clean
