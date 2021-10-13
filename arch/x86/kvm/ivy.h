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
int ivy_kvm_dsm_handle_req(void *data);
int ivy_kvm_dsm_page_fault(struct kvm *kvm, struct kvm_memory_slot *memslot,
		gfn_t gfn, bool is_smm, int write, int *type);

enum kvm_dsm_pf_type {
	DSM_PF_FAST,
	DSM_PF_WRITE_INIT,
	DSM_PF_WRITE_LOC,
	DSM_PF_WRITE_NET,
	DSM_PF_READ_INIT,
	DSM_PF_READ_NET,
	DSM_PF_ERR,
	DSM_PF_TYPES
};



#endif /* ARCH_X86_KVM_IVY_H */
