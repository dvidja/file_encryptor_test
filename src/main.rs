use core::panic;
use std::{path::{Path}, os::unix::prelude::FileExt};
use clap::Parser;
use std::fs;
use rand::Rng;

const BUFFER_SIZE : usize = 512;
const PREFIX_SIZE : usize = 16;

/// Test programm to xor files
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// file to encrypt or decrypt
    #[clap(short, long)]
    file: String,

    /// key
    #[clap(short, long)]
    key: String,

    /// mode : encrypt(e) or decrypt(d)
    #[clap(short, long)]
    mode: String,
}


fn main() {
    let args = Args::parse();

    let file_path = Path::new(&args.file);
    if !file_path.exists() {
        println!("File is not exist !!!");
        return;
    }

    if args.key.is_empty() {
        println!("Key cannot be empty string !!!");
        return;
    }

    let key = args.key.as_bytes().to_vec();

    
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(args.file)
        .expect("Cannot open file");

    match &args.mode[..] {
        "encrypt" | "e" => {
            encrypt_file(&mut file, key, &xor);
        }
        "decrypt" | "d" => {
            decrypt_file(&mut file, key, &xor);  
        }
        _ => {
            panic!("Unknown mode");
        }
    
    }   
}


fn xor(x : u8, y: u8) -> u8 {
    x ^ y
}


fn generate_prefix(size: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();

    let mut iv = Vec::new();
    iv.reserve(size);

    for _ in 0..size {
        iv.push(rng.gen());
    }
    
    iv
}

fn encrypt_file(file: &mut fs::File, key: Vec<u8>, process_fn: &dyn Fn(u8, u8) -> u8) {
    let file_size = file.metadata().unwrap().len();

    let prefix = generate_prefix(PREFIX_SIZE);
    
    let mut result =  Vec::new();
    result.reserve(PREFIX_SIZE + BUFFER_SIZE);
 
    let mut position = 0;
    for i in 0..prefix.len() {
        result.push(process_fn(prefix[i], key[i % key.len()]));
    }

    position += prefix.len();
    let mut buffer =  [0u8; BUFFER_SIZE];
    let mut write_offset = 0;
    let mut read_offset = 0;
    loop {
        let read_size = file.read_at(&mut buffer[..], read_offset).expect("Read file error");
        read_offset += read_size as u64;

        if !result.is_empty() {
            
            let write_size = file.write_at(result.as_slice(), write_offset).expect("Write file error");

            write_offset += write_size as u64;
            result.clear();
        }

        for i in 0..read_size {
            result.push(process_fn(buffer[i], key[position % key.len()]));
            position += 1;
        }

        if position >= file_size as usize + PREFIX_SIZE {
            file.write_at(result.as_slice(), write_offset).expect("Write file error");
            return;
        }
    }

}

fn decrypt_file(file: &mut fs::File, key: Vec<u8>, process_fn: &dyn Fn(u8, u8) -> u8) {
    let file_size = file.metadata().unwrap().len();

    let mut result_buffer: Vec<u8> =  Vec::new();
    result_buffer.reserve(BUFFER_SIZE);
    
    let mut position = PREFIX_SIZE;

    let mut read_buffer =  [0u8; BUFFER_SIZE];

    let mut write_offset = 0;
    let mut read_offset = PREFIX_SIZE as u64;
    loop {
        let read_size = file.read_at(&mut read_buffer[..], read_offset).expect("Read file error");
        read_offset += read_size as u64;

        for i in 0..read_size {
            result_buffer.push(process_fn(read_buffer[i], key[position % key.len()]));
            position += 1;
        }

        let write_size = file.write_at(result_buffer.as_slice(), write_offset).expect("Write file error");
        write_offset += write_size as u64;
        result_buffer.clear();

        if position >= file_size as usize {        
            file.set_len(file_size - PREFIX_SIZE as u64).expect("Error file resize");
            return;
        }
    }

}