#ifndef ARCH_X86_KVM_IVY_H
#define ARCH_X86_KVM_IVY_H

int ivy_kvm_dsm_handle_req(void *data);
int ivy_kvm_dsm_page_fault(struct kvm *kvm, struct kvm_memory_slot *memslot,
		gfn_t gfn, bool is_smm, int write);

#endif /* ARCH_X86_KVM_IVY_H */
