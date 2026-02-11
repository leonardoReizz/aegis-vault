use rand::Rng;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct PasswordOptions {
    pub length: usize,
    pub uppercase: bool,
    pub lowercase: bool,
    pub numbers: bool,
    pub symbols: bool,
}

const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NUMBERS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()_+-=[]{}|;:,.<>?";

pub fn generate(options: &PasswordOptions) -> Result<String, String> {
    let mut charset = String::new();

    if options.lowercase {
        charset.push_str(LOWERCASE);
    }
    if options.uppercase {
        charset.push_str(UPPERCASE);
    }
    if options.numbers {
        charset.push_str(NUMBERS);
    }
    if options.symbols {
        charset.push_str(SYMBOLS);
    }

    if charset.is_empty() {
        return Err("At least one character type must be selected".to_string());
    }

    let length = options.length.clamp(4, 128);
    let chars: Vec<char> = charset.chars().collect();
    let mut rng = rand::rngs::OsRng;

    let password: String = (0..length)
        .map(|_| chars[rng.gen_range(0..chars.len())])
        .collect();

    Ok(password)
}
