#!/bin/bash

rmmod kvm_intel
rmmod kvm
insmod /home/sin/Linux-DSM-TCP/arch/x86/kvm/kvm.ko
insmod /home/sin/Linux-DSM-TCP/arch/x86/kvm/kvm-intel.ko


