use std::fmt::Write;
use std::io::{self, Read};
use std::num::ParseIntError;

pub struct Sha256 {
    buffer: [u8; 64],
    buffer_len: usize,
    block_count: usize,
    state: [u32; 8],
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            buffer: [0; 64],
            buffer_len: 0,
            block_count: 0,
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
        }
    }

    pub fn absorb(&mut self, data: &[u8]) {
        for &byte in data {
            self.process_byte(byte);
        }
    }

    fn process_byte(&mut self, byte: u8) {
        self.buffer[self.buffer_len] = byte;
        self.buffer_len += 1;
        if self.buffer_len == 64 {
            self.process_block();
            self.buffer.fill(0);
            self.block_count += 1;
            self.buffer_len = 0;
        }
    }

    fn process_block(&mut self) {
        let mut w = [0u32; 64];
        for (chunk, word) in self.buffer.chunks(4).zip(w.iter_mut()) {
            *word = u32::from_be_bytes(chunk.try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ w[i - 15] >> 3;
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ w[i - 2] >> 10;
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut state = self.state;
        for i in 0..64 {
            let s1 =
                state[4].rotate_right(6) ^ state[4].rotate_right(11) ^ state[4].rotate_right(25);
            let ch = (state[4] & state[5]) ^ ((!state[4]) & state[6]);
            let temp1 = state[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 =
                state[0].rotate_right(2) ^ state[0].rotate_right(13) ^ state[0].rotate_right(22);
            let maj = (state[0] & state[1]) ^ (state[0] & state[2]) ^ (state[1] & state[2]);
            let temp2 = s0.wrapping_add(maj);
            state[7] = state[6];
            state[6] = state[5];
            state[5] = state[4];
            state[4] = state[3].wrapping_add(temp1);
            state[3] = state[2];
            state[2] = state[1];
            state[1] = state[0];
            state[0] = temp1.wrapping_add(temp2);
        }
        for (s, state_val) in self.state.iter_mut().zip(state.iter()) {
            *s = s.wrapping_add(*state_val);
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let total_bits = (self.buffer_len * 8) + (self.block_count * 512);
        let padding_len = (448 - total_bits % 512) % 512;
        let mut padded_buffer = Vec::with_capacity(padding_len as usize / 8 + 8);
        padded_buffer.push(0x80);
        padded_buffer.extend(vec![0; (padding_len / 8) as usize]);
        padded_buffer.extend((total_bits as u64).to_be_bytes());

        self.absorb(&padded_buffer);
        let mut hash = [0u8; 32];
        for (chunk, state_val) in hash.chunks_mut(4).zip(self.state.iter()) {
            chunk.copy_from_slice(&state_val.to_be_bytes());
        }
        hash
    }
}

fn decode_hex(hex_str: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..hex_str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16))
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| format!("{:02x}", b)).collect()
}

fn main() {
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read input");

    let inputs: Vec<&str> = input.trim().split_whitespace().collect();
    if inputs.len() != 2 {
        eprintln!("Invalid input format");
        return;
    }

    let mut hasher = Sha256::new();
    hasher.absorb(inputs[1].as_bytes());
    let hashed_output = hasher.finalize();

    let expected_output = decode_hex(inputs[0]).expect("Failed to decode hex");
    assert_eq!(hashed_output.to_vec(), expected_output);

    println!("{}", true);
}

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
