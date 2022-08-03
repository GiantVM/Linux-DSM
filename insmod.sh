#!/bin/bash

cd /mnt/sdb/snake0/giantvm/Euler_compile_env/home/Linux-DSM/arch/x86/kvm
modprobe -r kvm_intel
modprobe -r kvm
modprobe irqbypass
insmod kvm.ko
insmod kvm-intel.ko

