# Netfilter monitor

UNAME_S := $(shell uname -s)
HAS_APT := $(shell command -v apt-get 2> /dev/null)
HAS_YUM := $(shell command -v yum 2> /dev/null)
HAS_DNF := $(shell command -v dnf 2> /dev/null)

help:
	@echo "Netfilter Monitor - Available Commands:"
	@echo ""
	@echo "  bcc-monitor     Run the network monitor (requires sudo)"
	@echo "  setup-bcc       Make nfdump.py executable"
	@echo "  check-bcc       Check if BCC is installed"
	@echo "  install-bcc     Install BCC using system package manager"
	@echo "  help            Show this help message"
	@echo ""
	@echo "Usage: make <command>"

bcc-monitor:
	sudo python3 nfdump.py

setup-bcc:
	chmod +x nfdump.py

check-bcc:
	@echo "checking bcc installation."
	@python3 -c "import bcc; print('BCC is installed')" 2>/dev/null || $(MAKE) install-bcc-help

install-bcc:
ifdef HAS_APT
	@echo "Install bcc by apt."
	sudo apt update
	sudo apt install -y bpfcc-tools python3-bpfcc
else ifdef HAS_DNF
	@echo "Install bcc by dnf."
	sudo dnf install -y bcc-tools python3-bcc
else ifdef HAS_YUM
	@echo "Install bcc by yum."
	sudo yum install -y bcc-tools python3-bcc
else
	@echo "Error, no supported package manager found.."
	@echo "Please install BCC manually"
	@exit 1
endif

install-bcc-help:
	@echo "BCC not found."
	@echo ""
	@echo "BCC (Berkeley Packet Filter Compiler Collection) is required to run this network monitor."
	@echo ""
	@echo "Installation options:"
	@echo "  1. Use make install-bcc (auto-detects package manager)"
	@echo "  2. Manual installation:"
	@echo ""
	@echo "     Ubuntu/Debian:"
	@echo "       sudo apt update && sudo apt install -y bpfcc-tools python3-bpfcc"
	@echo ""
	@echo "     RHEL/CentOS/Fedora (dnf):"
	@echo "       sudo dnf install -y bcc-tools python3-bcc"
	@echo ""
	@echo "     RHEL/CentOS (yum):"
	@echo "       sudo yum install -y bcc-tools python3-bcc"
	@echo ""
	@echo "After installation, run 'make check-bcc' to verify."

.PHONY: help setup-bcc check-bcc install-bcc install-bcc-help
