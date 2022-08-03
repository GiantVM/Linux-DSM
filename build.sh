#!/bin/bash
make -j30 -C `pwd` M=`pwd`/arch/x86/kvm clean
make -j30 -C `pwd` M=`pwd`/arch/x86/kvm modules



