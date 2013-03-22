# From hello_tutorial from the Native Client project.
#
# -Original liscence-
# Copyright (c) 2012 The Native Client Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

PROJECT:=openssl_exp_extension
LDFLAGS:=-lppapi_cpp -lppapi -lssl -lcrypto -lglibc-compat -lnosys
CXX_SOURCES:=$(PROJECT).cc

THIS_MAKEFILE:=$(abspath $(lastword $(MAKEFILE_LIST)))
# NACL_SDK_ROOT?=$(abspath $(dir $(THIS_MAKEFILE))../..)
NACL_SDK_ROOT?=/home/dmiyakawa/utils/nacl_sdk/pepper_25

# Project Build flags
WARNINGS:=-Wno-long-long -Wall -Wswitch-enum -pedantic
CXXFLAGS:=-pthread -std=gnu++98 $(WARNINGS)

# Compute tool paths
OSNAME:=$(shell python $(NACL_SDK_ROOT)/tools/getos.py)
TC_PATH:=$(abspath $(NACL_SDK_ROOT)/toolchain/$(OSNAME)_x86_newlib)
CXX:=$(TC_PATH)/bin/i686-nacl-g++

#
# Disable DOS PATH warning when using Cygwin based tools Windows
#
CYGWIN ?= nodosfilewarning
export CYGWIN


# Declare the ALL target first, to make the 'all' target the default build
all: $(PROJECT)_x86_32.nexe $(PROJECT)_x86_64.nexe

# Define 32 bit compile and link rules for main application
x86_32_OBJS:=$(patsubst %.cc,%_32.o,$(CXX_SOURCES))
$(x86_32_OBJS) : %_32.o : %.cc $(THIS_MAKE)
	$(CXX) -o $@ -c $< -m32 -O0 -g $(CXXFLAGS) $(INCLUDES_32) 

$(PROJECT)_x86_32.nexe : $(x86_32_OBJS)
	$(CXX) -o $@ $^ -m32 -O0 -g $(CXXFLAGS) $(LDFLAGS)

# Define 64 bit compile and link rules for C++ sources
x86_64_OBJS:=$(patsubst %.cc,%_64.o,$(CXX_SOURCES))
$(x86_64_OBJS) : %_64.o : %.cc $(THIS_MAKE)
	$(CXX) -o $@ -c $< -m64 -O0 -g $(CXXFLAGS) $(INCLUDES_64) 

$(PROJECT)_x86_64.nexe : $(x86_64_OBJS)
	$(CXX) -o $@ $^ -m64 -O0 -g $(CXXFLAGS) $(LDFLAGS)

.PHONY: clean
clean:
	rm *.o *.nexe
