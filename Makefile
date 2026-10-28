ARCHES := x86 arm

# start-cli 1.1.0 hardcodes this local tag. Seed it from an immutable image
# and verify the binding before and after packing on the selected daemon.
STARTOS_UTILS_IMAGE := ghcr.io/start9labs/sdk/utils@sha256:718da8a501695e41102daf0847532b1af19b3ca516efa9f04e3ad24363efb00d
STARTOS_UTILS_TAG := ghcr.io/start9labs/sdk/utils:latest

include s9pk.mk

.PHONY: startos-utils startos-utils-check
startos-utils:
	docker pull $(STARTOS_UTILS_IMAGE)
	docker tag $(STARTOS_UTILS_IMAGE) $(STARTOS_UTILS_TAG)
	@$(MAKE) --no-print-directory startos-utils-check

startos-utils-check:
	@expected=$$(docker image inspect $(STARTOS_UTILS_IMAGE) --format '{{.Id}}') && \
	actual=$$(docker image inspect $(STARTOS_UTILS_TAG) --format '{{.Id}}') && \
	test -n "$$expected" && test "$$expected" = "$$actual"
