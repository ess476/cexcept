#!/bin/bash

ls -1a /usr/share/man/man2 > syscall.list
python3 sys_parser.py
