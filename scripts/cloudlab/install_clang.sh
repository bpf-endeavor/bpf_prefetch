#!/bin/bash
sudo apt install -y clang-14
sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-14 100 \
	--slave /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-14  \
	--slave /usr/bin/llvm-objdump llvm-objdump /usr/bin/llvm-objdump-14
