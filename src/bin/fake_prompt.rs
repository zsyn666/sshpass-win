use std::io::{self, BufRead, Write};

fn main() {
    let expected = std::env::var("FAKE_PROMPT_PASSWORD").unwrap_or_else(|_| "secret".to_string());
    print!("Password: ");
    io::stdout().flush().unwrap();
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line).unwrap();
    let got = line.trim_end_matches(['\r', '\n']);
    if got == expected {
        println!("AUTH_OK");
    } else {
        println!("AUTH_FAIL:{}", got);
        std::process::exit(7);
    }
}
