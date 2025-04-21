PKG=github.com/smallstep/ssh-sk-attest-proxy
SRC=$(shell find . -type f -name '*.go')

PREFIX?=bin

all: build

build: $(PREFIX)/ssh_ca_attest $(PREFIX)/verify_ssh_sk_attestation

$(PREFIX)/ssh_ca_attest: $(SRC)
	@mkdir -p $(PREFIX)
	@go build -o $(PREFIX)/ssh_ca_attest $(PKG)/cmd/ssh_ca_attest

$(PREFIX)/verify_ssh_sk_attestation: $(SRC)
	@mkdir -p $(PREFIX)
	@go build -o $(PREFIX)/verify_ssh_sk_attestation $(PKG)/cmd/verify_ssh_sk_attestation

clean: $(PREFIX)/ssh_ca_attest $(PREFIX)/verify_ssh_sk_attestation
	@rm -f $(PREFIX)/ssh_ca_attest $(PREFIX)/verify_ssh_sk_attestation
