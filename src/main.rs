use cheat::infinite_arrows;

mod cheat;

#[macro_use]
extern crate anyhow;

fn main() {
    // Result<(), Box<dyn std::error::Error>>
    if let Err(why) = infinite_arrows() {
        eprintln!("error: {}", why);
    };

}