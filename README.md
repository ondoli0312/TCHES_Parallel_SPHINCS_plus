# TCHES_Parallel_SPHINCS_plus

This code is a SPHINCS+ code submitted to TCHES_2023 (title : Parallel Implementation of SPHINCS+ with GPUs). The description of compiling and building is as follows.

[Build]
1. Our code is implemented via CUDA. We used Visual studio 2019 version, and cuda runtime used 10.2. CUDA runtime and IDE are required to build our code on the Windows operating system.

2. To build our code on the Linux operating system we need the nvcc NVIDIA CUDA compiler.

[Code]
1. Our code consists of security_level_x and security_level_x_throughput (where x is 1 or 3 or 5). 

2. The security_level project is our latency-oriented SPHINCS+ code. The code provides the minimum latency of SPHINCS+ signing for one message. Our latency-oriented SPHINCS+ codes provide NIST security levels 1, 3, and 5 respectively.
