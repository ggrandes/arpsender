#!/bin/sh
gcc -static -o bin/arpsender.$(uname -i) net.c tap.c util.c main.c
