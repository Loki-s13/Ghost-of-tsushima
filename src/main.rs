use cheat::process_id;

mod cheat;

#[macro_use]
extern crate anyhow;

fn main() {
    let test = process_id("AdjustService.exe").unwrap();
    println!("Process ID: {}", test);
}