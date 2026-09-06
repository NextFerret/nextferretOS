# Arvor Linux Core Build System
# Compiles napt, nsm, nlc with high-performance optimizations (-O3, -flto)

CC ?= gcc
CXX ?= g++
CFLAGS ?= -O3 -flto -pipe -Wall -Wextra -D_GNU_SOURCE
CXXFLAGS ?= -std=c++17 -O3 -flto -pipe -Wall -Wextra -D_GNU_SOURCE
LDFLAGS ?= -flto

PREFIX ?= /usr
DESTDIR ?=
BINDIR ?= $(DESTDIR)$(PREFIX)/bin
DATADIR ?= $(DESTDIR)$(PREFIX)/share
SYSCONFDIR ?= $(DESTDIR)/etc
AUTOSTARTDIR ?= $(SYSCONFDIR)/xdg/autostart
SYSTEMDDIR ?= $(DESTDIR)/etc/systemd/system
INITRAMFS_HOOKS ?= $(DESTDIR)/etc/initramfs-tools/hooks
INITRAMFS_SCRIPTS ?= $(DESTDIR)/etc/initramfs-tools/scripts/local-top
GRUBDIR ?= $(DESTDIR)/etc/grub.d

APT_LIBS ?= -lapt-pkg -lpthread
ARCH := $(shell uname -m)

all: napt nsm nlc

napt: usr/bin/napt.cpp
	@echo "  CXX     usr/bin/napt.cpp -> napt ($(ARCH))"
	@$(CXX) $(CXXFLAGS) usr/bin/napt.cpp $(APT_LIBS) $(LDFLAGS) -o napt || \
		(echo "Note: libapt-pkg-dev required to build napt binary directly on host." && true)

nsm: usr/bin/nsm.c
	@echo "  CC      usr/bin/nsm.c -> nsm"
	@$(CC) $(CFLAGS) usr/bin/nsm.c $(LDFLAGS) -o nsm

nlc: usr/bin/nlc.c
	@echo "  CC      usr/bin/nlc.c -> nlc"
	@$(CC) $(CFLAGS) usr/bin/nlc.c $(LDFLAGS) -o nlc

install: all
	@echo "  INSTALL Installing Arvor Linux binaries and services to $(DESTDIR)..."
	install -d $(BINDIR)
	install -d $(SYSCONFDIR)/napt
	install -d $(SYSTEMDDIR)
	install -d $(INITRAMFS_HOOKS)
	install -d $(INITRAMFS_SCRIPTS)
	install -d $(GRUBDIR)

	# Binaries
	[ -f napt ] && install -m 755 napt $(BINDIR)/napt || true
	[ -f nsm ] && install -m 755 nsm $(BINDIR)/nsm || true
	[ -f nlc ] && install -m 755 nlc $(BINDIR)/nlc || true
	install -m 755 usr/bin/arvorctl $(BINDIR)/arvorctl
	install -m 755 usr/bin/arvor-boot-success $(BINDIR)/arvor-boot-success
	install -m 755 usr/bin/arvor-guard $(BINDIR)/arvor-guard
	install -m 755 usr/bin/nsmd_start $(BINDIR)/nsmd_start || true
	install -m 755 usr/bin/nextferretinstall $(BINDIR)/nextferretinstall || true

	# Systemd Units
	install -m 644 etc/systemd/system/arvor-boot-success.service $(SYSTEMDDIR)/arvor-boot-success.service
	install -m 644 etc/systemd/system/arvor-guard.service $(SYSTEMDDIR)/arvor-guard.service
	install -m 644 etc/systemd/system/arvor-guard.timer $(SYSTEMDDIR)/arvor-guard.timer

	# Initramfs & GRUB
	install -m 755 etc/initramfs-tools/hooks/arvor_lvm_rollback $(INITRAMFS_HOOKS)/arvor_lvm_rollback
	install -m 755 etc/initramfs-tools/scripts/local-top/arvor_lvm_snapshot $(INITRAMFS_SCRIPTS)/arvor_lvm_snapshot
	install -m 755 etc/grub.d/10_arvor_snapshots $(GRUBDIR)/10_arvor_snapshots

clean:
	@echo "  CLEAN   Removing compiled binaries"
	rm -f napt nsm nlc *.o

iso:
	@echo "  ISO     Executing ISO generator..."
	bash ./create-iso.sh

help:
	@echo "Arvor Linux Build Targets:"
	@echo "  make all       - Compile all core binaries (napt, nsm, nlc)"
	@echo "  make install   - Install all system utilities, initramfs hooks & systemd units"
	@echo "  make iso       - Generate bootable live ISO image"
	@echo "  make clean     - Remove compiled artifacts"

.PHONY: all napt nsm nlc install clean iso help
