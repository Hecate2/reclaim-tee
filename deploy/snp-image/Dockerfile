# Throwaway image-build environment for the two-tier SEV-SNP image (base UKI +
# app partition). Uses ukify + systemd-repart (two-tier UKI, no full-OS rootfs). Run
# privileged with /dev mounted for the loop-free systemd-repart disk assembly.
# Base pinned by digest so a rebuilt tag can't drift the UKI. Defaults match pins.env.
ARG UBUNTU_DIGEST=sha256:786a8b558f7be160c6c8c4a54f9a57274f3b4fb1491cf65146521ae77ff1dc54
FROM ubuntu:24.04@${UBUNTU_DIGEST}

ENV DEBIAN_FRONTEND=noninteractive

# Cloud-specific kernel: linux-image-gcp or linux-image-aws. Each ships a few
# non-builtin modules the loader bundles+inserts (gve on GCP, sev-guest on AWS).
ARG KERNEL_PKG=linux-image-gcp

# Every tool whose output lands in the measured base UKI is version-pinned
# (snp-image/pins.env -> these build-args): the stub + ukify build it, zstd/cpio
# compress+archive the initrd, binutils backs ukify's PE assembly, systemd ships
# systemd-measure. dosfstools/mtools/python3 only touch the unmeasured disk.
ARG SYSTEMD_BOOT_VER=255.4-1ubuntu8.16
ARG SYSTEMD_UKIFY_VER=255.4-1ubuntu8.16
ARG SYSTEMD_VER=255.4-1ubuntu8.16
ARG ZSTD_VER=1.5.5+dfsg2-2build1.1
ARG CPIO_VER=2.15+dfsg-1ubuntu2
ARG BINUTILS_VER=2.42-4ubuntu2.10
RUN apt-get update && apt-get install -y --no-install-recommends \
        "systemd=${SYSTEMD_VER}" \
        "systemd-boot-efi=${SYSTEMD_BOOT_VER}" "systemd-ukify=${SYSTEMD_UKIFY_VER}" \
        dosfstools mtools \
        "zstd=${ZSTD_VER}" "cpio=${CPIO_VER}" "binutils=${BINUTILS_VER}" \
        "${KERNEL_PKG}" ca-certificates \
        python3 \
    && rm -rf /var/lib/apt/lists/*
