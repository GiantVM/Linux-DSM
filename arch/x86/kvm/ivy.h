#ifndef ARCH_X86_KVM_IVY_H
#define ARCH_X86_KVM_IVY_H
/*
 * Copyright (C) 2019, Trusted Cloud Group, Shanghai Jiao Tong University.
 * 
 * Authors:
 *   Jin Zhang <jzhang3002@sjtu.edu.cn>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */
struct kvm_dsm_memory_slot;

int __ivy_kvm_dsm_page_fault_slow(struct kvm *kvm, gfn_t gfn, bool is_smm, struct kvm_memory_slot *memslot,
		int write, struct kvm_dsm_memory_slot *slot, hfn_t vfn, bool local);

int ivy_kvm_dsm_handle_req(void *data);

int kvm_arch_setup_ivy_dsm_async_pf(struct kvm_vcpu *vcpu, gfn_t gfn, bool is_smm,
		struct kvm_memory_slot *memslot, int write,
		struct kvm_dsm_memory_slot *slot, hfn_t vfn);

int ivy_kvm_dsm_page_fault(struct kvm *kvm, struct kvm_memory_slot *memslot,
		gfn_t gfn, bool is_smm, int write);
int ivy_kvm_dsm_vcpu_page_fault(struct kvm_vcpu *vcpu, struct kvm_memory_slot *memslot,
		gfn_t gfn, bool is_smm, int write);
int ivy_kvm_dsm_vcpu_page_fault_async(struct kvm_vcpu *vcpu, struct kvm_memory_slot *memslot,
		gfn_t gfn, bool is_smm, int write);

#endif /* ARCH_X86_KVM_IVY_H */
