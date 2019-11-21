# Cascade Lake Management Engine Firmware
These ME binaries are intended to be used with 2nd Generation Intel&reg; Xeon&reg; Scalable Processors and chipsets formerly known as Cascade Lake.

## Ignition Firmware Overview
Ignition Firmware is a variant of ME firmware that is intended to provide lightweight chipset initialization. It does not contain all the features of the Intel&reg; Server Platform Services (SPS) ME firmware. Ignition Firmware is consequently much smaller than Intel&reg; SPS Firmware (~0.5 MB vs. ~3 MB). Both Intel&reg; SPS Firmware and Ignition Firmware are specifically designed for server platforms with Intel&reg; Xeon&reg; Processors and are different than the ME firmware found on client platforms. These binaries cannot be used on 1 socket High End Desktop (HEDT) platforms like Glacier Falls or Basin Falls. Glacier Falls and Basin Falls platforms use client ME firmware images.
