OUTPUT_DIR := bin
LDFLAGS    := -s -w
GOFLAGS    := -trimpath -ldflags="$(LDFLAGS)"

# Native binary suffix — Windows needs .exe.
ifeq ($(OS),Windows_NT)
EXE := .exe
else
EXE :=
endif

# Binaries this repo ships. Each entry is "<name>:./cmd/<name>".
CMDS := operator gasoctl client

.PHONY: all build operator gasoctl client \
        linux linux-arm64 windows clean \
        bench-csc-udp bench-csc-quic \
        bench-cssc-udp bench-cssc-quic

all: build

# Native build of every binary into $(OUTPUT_DIR)/.
build: $(addprefix $(OUTPUT_DIR)/, $(addsuffix $(EXE), $(CMDS)))

$(OUTPUT_DIR)/%$(EXE): cmd/%
	@mkdir -p $(OUTPUT_DIR)
	go build $(GOFLAGS) -o $@ ./cmd/$*

# Convenience aliases — `make operator`, `make client`, etc.
operator:   $(OUTPUT_DIR)/operator$(EXE)
gasoctl:    $(OUTPUT_DIR)/gasoctl$(EXE)
client:     $(OUTPUT_DIR)/client$(EXE)

# Cross-builds. Each target produces all four binaries with a suffix.
linux:
	@mkdir -p $(OUTPUT_DIR)
	@for c in $(CMDS); do \
	  echo "==> linux/amd64 $$c"; \
	  CGO_ENABLED=0 GOOS=linux  GOARCH=amd64 go build $(GOFLAGS) -o $(OUTPUT_DIR)/$$c-linux-amd64    ./cmd/$$c || exit 1; \
	done

linux-arm64:
	@mkdir -p $(OUTPUT_DIR)
	@for c in $(CMDS); do \
	  echo "==> linux/arm64 $$c"; \
	  CGO_ENABLED=0 GOOS=linux  GOARCH=arm64 go build $(GOFLAGS) -o $(OUTPUT_DIR)/$$c-linux-arm64    ./cmd/$$c || exit 1; \
	done

windows:
	@mkdir -p $(OUTPUT_DIR)
	@for c in $(CMDS); do \
	  echo "==> windows/amd64 $$c"; \
	  CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -o $(OUTPUT_DIR)/$$c-windows-amd64.exe ./cmd/$$c || exit 1; \
	done

clean:
	rm -rf $(OUTPUT_DIR)

# bench-{topology}-{transport}
# topology: csc (client-server-client), cssc (client-server-server-client)
# transport: udp, quic
bench-csc-udp:
	go test ./tests/ -v -run TestCSC_UDP -timeout 120s

bench-csc-quic:
	go test ./tests/ -v -run TestCSC_QUIC -timeout 120s


bench-cssc-udp:
	go test ./tests/ -v -run TestCSSC_UDP -timeout 120s

bench-cssc-quic:
	go test ./tests/ -v -run TestCSSC_QUIC -timeout 120s

