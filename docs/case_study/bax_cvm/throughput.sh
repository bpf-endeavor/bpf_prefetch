#!/bin/bash
echo "# Batch size 4 ========================"
cat data/batch_size_4.txt | grep thro | tr '(' ' ' | awk '{print $7}' | ../../stats.py
echo "# Batch size 8 ========================"
cat data/batch_size_8.txt | grep thro | tr '(' ' ' | awk '{print $7}' | ../../stats.py
echo "# Batch size 16 ========================"
cat data/batch_size_16.txt | grep thro | tr '(' ' ' | awk '{print $7}' | ../../stats.py
echo "# Batch size 32 ======================== "
cat data/batch_size_32.txt | grep thro | tr '(' ' ' | awk '{print $7}' | ../../stats.py
