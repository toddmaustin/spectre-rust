# Spectre V1 Proof-of-Concept Attack in the Rust Language


## Introduction

In Rust We Trust?!?!

This repo implemented a working Spectre V1 for the Rust language. Using our Spectre V1 transient execution attack, the attack code is able to force a bounds-checked Rust array variable access to read any byte in the Rust application's memory. This attack should be of interest to Rust developers, since Rust is a memory-safe language, and this attack performs an arbitrary buffer overread, thereby demonstrating a vulnerability in Rusts' ability to stop memory access errors.

The developers of this attack PoC are big fans of Rust, it is truly a security-minded language with array bounds checking, integer overflow detection, etc... But 5 years after Spectre was disclosed it is still quite vulnerable to this attack and likely other microarchitectural attacks. The mission of this project is to create a reliable Spectre proof-of-concept attack that Rust compiler and runtime developers can utilize to test their mitigations.

This proof of concept attack has successfully run on a 13th-gen Core i7-13700H on Ubuntu 20.04 inside VirtualBox 7.0 on Windows 11. Built with rustc compiler version 1.73.0.

Spectre V1 is a difficult to stop buffer overread attack that plagues many of today's high-performance microprocessors, to learn more about this microarchitectural attack, please check out the [wiki page](https://en.wikipedia.org/wiki/Spectre_(security_vulnerability)).

## Prerequisites

You'll need to have the following:

  - rustc compiler based on LLVM
  - cargo Rust package manager
  - an x86-based out-of-order core running Linux (inside VirtualBox is fine)

## Building the attack application and running an attack experiment

To build the attack binary:
```
cargo build
```

To run an attack test:
```
cargo run
```

## Getting the Spectre V1 attack to work

Spectre attacks occur in the mispeculation stream of a high-performance processor, which has a lot of failure modes, so you may have to work through some adjustments to get the attack to work on your system. But when the attack is working it will look something like this:
```
Finished dev [optimized + debuginfo] target(s) in 0.01s
Running `target/debug/rust-spectre`
Distance to secret array = 46121323748004 (0x560a203f3ad0 -> 0x7ffc955d9574)
Running Spectre V1 attack tests...
Char: '~', Score: 284272, Sum: 166
Char: '~', Score: 286790, Sum: 0
Char: '~', Score: 284160, Sum: 166
Char: '~', Score: 278370, Sum: 0
Char: '~', Score: 286304, Sum: 166
Char: '~', Score: 286800, Sum: 0
Char: '~', Score: 276748, Sum: 166
Char: '~', Score: 291342, Sum: 0
Char: '~', Score: 293152, Sum: 166
Char: '~', Score: 274158, Sum: 0
Char: '~', Score: 270710, Sum: 166
Char: '~', Score: 282374, Sum: 0
Char: 'H', Score: 100996, Sum: 166
Char: 'e', Score: 102160, Sum: 0
Char: 'l', Score: 122062, Sum: 166
Char: 'l', Score: 117292, Sum: 0
Char: 'o', Score: 127474, Sum: 166
Char: ' ', Score: 129794, Sum: 0
 .
 .
 .
Char: 'l', Score: 95332, Sum: 0
Char: 'o', Score: 80862, Sum: 166
Char: ' ', Score: 80188, Sum: 0
Char: 'W', Score: 103408, Sum: 166
Char: 'o', Score: 93944, Sum: 0
Char: 'r', Score: 81772, Sum: 166
Char: 'l', Score: 96640, Sum: 0
Char: 'd', Score: 108080, Sum: 166
Char: ' ', Score: 84658, Sum: 0
Char: 'H', Score: 88134, Sum: 166
Char: 'e', Score: 100820, Sum: 0
Char: 'l', Score: 82778, Sum: 166
Char: 'l', Score: 86246, Sum: 0
Char: 'o', Score: 90166, Sum: 166
Char: ' ', Score: 89542, Sum: 0
Char: ' ', Score: 93434, Sum: 166
Char: ' ', Score: 79870, Sum: 0
Guessed secret = `~~,~~~~~~~~~Hello   Hello World Hello   Hello World Hello   '
NOTE: Required to stop dead code removal: Sum: 0
Final stats: 79.67% correct guesses. (239 out of 300 letters).
  (Note: random guessing of the string would have an accuracy of roughly: 0.39%)
```
This experiment worked and was able to achieve a 79.67% accuracy at accessing the entries in array SECRET[] from the bounds-checked Rust array ARR1[]. Also note that the success rate of just guessing letters would be no higher than 0.39%, so any accuracy much great than 1% indicates that Spectre V1 is working on the system running the attack program.

Note that there are many ways for this attack to fail: i) your system mitigates Spectre V1 (unlikely), ii) memory alignments do not allow the attack PoC to properly flush the cache and create enough delay for a successful speculative execution attack, or iii) system background executions are interferring with the branch-predictor and cache side channels. The attack code will detect if the attack is not working (with a low secret guess rate) and stop early, which will look like this:
```
Finished dev [optimized + debuginfo] target(s) in 0.00s
Running `target/debug/rust-spectre`
Distance to secret array = 46825600727508 (0x55677891dad0 -> 0x7ffde7de14a4)
Running Spectre V1 attack tests...
Char: '~', Score: 273206, Sum: 166
Char: '~', Score: 245110, Sum: 0
Char: '~', Score: 249758, Sum: 166
 .
 .
 .
Char: '~', Score: 257746, Sum: 0
Char: '~', Score: 250570, Sum: 166
Char: '/', Score: 260254, Sum: 0
Char: '~', Score: 235916, Sum: 166
Char: '~', Score: 228660, Sum: 0
Guessed secret = `~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~A~~~~~~~~,~~~~,A~~~~~~~~~/~~'
NOTE: Required to stop dead code removal: Sum: 0
This target mitigates Spectre V1 or memory alignment does not permit the attack, rebuild and rerun to attempt again...
```

If this occurs, rebuild and rerun the program 20 more times, if you don't see any successful infiltration of secret data, then the attack will not work on you system.

## Licensing Details

This attack code is made available for use under the [Apache License, version 2.0](https://www.apache.org/licenses/LICENSE-2.0) 

## Spectre V1 Attack PoC Authors

- Christopher Felix, University of Michigan
- Donayam Benti, University of Michigan
- [Todd Austin](https://www.linkedin.com/in/prof-todd-austin/), University of Michigan and Agita Labs, [@ToddMAustin](https://twitter.com/ToddMAustin)

And, thanks to the respective authors of the C++ Spectre V1 attacks that inspired this work.

