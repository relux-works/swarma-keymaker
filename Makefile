# Place build/test artifacts in a caller-selected scratch directory.
SCRATCH ?= $(TMPDIR)
WINDOW_CONFIG ?=

.PHONY: test-core build-window test-multiuid

test-core:
	go test ./internal/keymaker ./cmd/keymaker ./internal/testwindow ./cmd/keymaker-window

build-window:
	@test -n "$(SCRATCH)" || { echo 'Set SCRATCH to an existing private scratch directory' >&2; exit 1; }
	go build -o "$(SCRATCH)/keymaker-window" ./cmd/keymaker-window

test-multiuid: build-window
	@set +e; "$(SCRATCH)/keymaker-window" -config "$(WINDOW_CONFIG)"; status=$$?; \
	case $$status in 0) label=PASS;; 1) label=FAILURE;; 2) label=CONFIGURATION;; 3) label=PENDING;; *) label=UNEXPECTED;; esac; \
	printf 'multiuid runner status: %s (%s)\n' "$$status" "$$label"; exit "$$status"
