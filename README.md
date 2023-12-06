# Spectre V1 Proof-of-Concept Attack in the Rust Language


## Introduction

This is the VIP-Bench Benchmark Suite, which is a collection of benchmarks to serve the evaluation of privacy-enhanced computation frameworks.
A privacy-enhance computation framework is one in which encrypted data can be directly processed without software needing to decrypt it.
These systems naturally enhance privacy since hacking into a system using privacy-enhanced computation only gives the attacker access
to ciphertext. Examples of privacy-enhanced computation frameworks that this benchmark suite wants to server are: homomorphic encryption,
runtime encryption, multi-party computation, etc.

*Why do we need a privacy-oriented benchmark suite?* Privacy-oriented programming has two primary impacts on software algorithms: first,
the algorithms become less heuristic since they can no longer inspect the data they are operating on; and second, the core datatypes will
be replaced with encrypted (and otherwise enhanced) data types. The VIP Benchmark Suite has already done this work for you, for a wide
range of application that suggest a strong need for data privacy.

*My privacy-enhanced computation framework doesn't work with some/all of the VIP benchmarks!* Yes, this may be the case
If you cannot support a benchmark, due to the data types it requires or the complexity of its
computation, perhaps you can benchmark without that particular application. Since some of the privacy-enhanced frameworks can do all of
these benchmarks, we felt it was important to take a greatest-common-demoninator approach to selecting benchmarks, rather than a
least-common-demoninator approach.  In any event, please help us build in support for your framework in our benchmark suite.

To learn more about VIP-Bench's design and implementation, please read the [VIP-Bench paper](https://drive.google.com/file/d/1aresSfrY_8C0gMtrcF0LRfTRGybESsA2/view?usp=sharing).

If you use the VIP-Bench benchmarks in your research and/or publications, please cite the VIP-Bench paper:

> Lauren Biernacki, Meron Zerihun Demissie, Kidus Birkayehu Workneh, Galane Basha Namomsa, Plato Gebremedhin, Fitsum Assamnew Andargie, Brandon Reagen, and Todd Austin, VIP-Bench: A Benchmark Suite for Evaluating Privacy-Enhanced Computation Frameworks, in the 2021 IEEE International Symposium on Secure and Private Execution Environment Design (SEED-2021), September 2021.

## Prerequisites

You'll need to have the following:

  - rustc compiler based on LLVM
  - cargo Rust package manager


## Building the attack application and running an attack experiment

To build the attack binary:
```
cargo build
```

To run an attack test:
```
cargo run
```

## Running VIP Benchmark Security Analysis

To assess the security of a privacy-enhanced computation framework, VIP-Bench performs indistinguishability analysis on sampled ciphertext from a running program. The ciphertext is analyzed using the DIEHARDER random test suite, which looks for any traces of information in the sampled ciphertext. To run these experiments, first install the DIEHARDER test suite (e.g., for Ubuntu):
```
sudo apt-get install -y dieharder
```

Next, build the SLICE-N-DICE application, which notably requires the underlying privacy-enhanced computation framework to implement the VIP_EMITCT() macro. To build and run the SLICE-N-DICE sampled ciphertext generator and then analyze the emitted ciphertext with DIEHARDER, use the following commands:
```
cd slice-n-dice
make MODE=enc clean build
./slice-n-dice SAMPLES.log 500000000
dieharder -a -g 202 -f SAMPLES.log
```

## Licensing Details

The portions of the benchmark suite that was build by the VIP Benchmark team are (C) 2019-2021 and available for use under
the [Apache License, version 2.0](https://www.apache.org/licenses/LICENSE-2.0) 

## Spectre V1 Attack PoC Authors

- Christopher Felix, University of Michigan
- Donayam Benti, University of Michigan
- Todd Austin, University of Michigan and Agita Labs

And, thanks to the respective authors of the C++ Spectre V1 attacks that inspired this work.

