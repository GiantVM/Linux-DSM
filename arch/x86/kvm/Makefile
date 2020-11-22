# Copyright (C) 2019, Trusted Cloud Group, Shanghai Jiao Tong University.
# 
# Authors:
#   Jin Zhang 	    <jzhang3002@sjtu.edu.cn>
#   Yubin Chen 	 	<binsschen@sjtu.edu.cn>
#   Zhuocheng Ding  <tcbbd@sjtu.edu.cn>
# 
#  This work is licensed under the terms of the GNU GPL, version 2.  See
#  the COPYING file in the top-level directory.

ccflags-y += -Iarch/x86/kvm

CFLAGS_x86.o := -I.
CFLAGS_svm.o := -I.
CFLAGS_vmx.o := -I.

KVM := ../../../virt/kvm

kvm-y			+= $(KVM)/kvm_main.o $(KVM)/coalesced_mmio.o \
				$(KVM)/eventfd.o $(KVM)/irqchip.o $(KVM)/vfio.o
kvm-$(CONFIG_KVM_ASYNC_PF)	+= $(KVM)/async_pf.o

kvm-y			+= x86.o mmu.o emulate.o i8259.o irq.o lapic.o \
			   i8254.o ioapic.o irq_comm.o cpuid.o pmu.o mtrr.o \
			   hyperv.o page_track.o debugfs.o

kvm-$(CONFIG_KVM_DEVICE_ASSIGNMENT)	+= assigned-dev.o iommu.o

kvm-$(CONFIG_KVM_DSM)			+= ktcp.o krdma.o dsm.o xbzrle.o \
								   dsm-util.o ivy.o \

kvm-intel-y		+= vmx.o pmu_intel.o
kvm-amd-y		+= svm.o pmu_amd.o

obj-$(CONFIG_KVM)	+= kvm.o
obj-$(CONFIG_KVM_INTEL)	+= kvm-intel.o
obj-$(CONFIG_KVM_AMD)	+= kvm-amd.o
