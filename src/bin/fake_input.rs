use std::io::{self, BufRead, Write};

fn main() {
    print!("Input: ");
    io::stdout().flush().unwrap();
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line).unwrap();
    println!("GOT:{}", line.trim_end_matches(['\r', '\n']));
}
