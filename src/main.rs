mod auth;
mod password_storage;
mod cli;

use std::io::{self, Write};
use clipboard::{ClipboardProvider, ClipboardContext};
use reedline::Signal;
use rpassword::read_password;
use zeroize::Zeroize;
use passwords::PasswordGenerator;
use crate::auth::*;
use crate::cli::MyPrompt;
use crate::password_storage::*;

static DEFAULT_PASSWORD_LEN: usize = 32;

fn main() {
    // Check if master password is set
    let mut master_key = if !master_password_exists() {
        // Set new master password
        println!("Nie znaleziono profilu.");
        let password: String;
        loop{
            let opt_password = password_input();

            match opt_password{
                Some(pass) => {
                    password = pass;
                    break;
                }            
                _ => {println!("Powtórzone hasło musi być identyczne jak pierwsze!");}
            }
        }

        let salt = generate_and_store_salt();
        let master_key = derive_master_key(&password, &salt);
        create_verification_token(&master_key);
        println!("Hasło ustawione.");

        master_key
    } else {
        // Load salt
        let salt = load_salt().expect("Salt file missing!");

        print!("Wprowadź hasło: ");
        io::stdout().flush().unwrap();
        let password = read_password().unwrap();

        let candidate_key = derive_master_key(&password, &salt);

        if !verify_master_key(&candidate_key) {
            println!("Niepoprawne hasło!");
            return;
        }

        candidate_key
    };

    // Storage with our encrypted passwords
    let mut vault = load_vault();

    // Prepare for REPL
    let commands = vec![
        String::from("new"),
        String::from("add"),
        String::from("remove"),
        String::from("get"),
        String::from("change-password"),
        String::from("help"),
        String::from("exit")
        ];

    // Set prompt
    let prompt = MyPrompt;

    let mut line_editor = cli::bulid_line_editor(vault.keys().cloned().collect(), commands.clone());

    // System's clipboard to copy passwords
    let mut clipboard: ClipboardContext = ClipboardProvider::new().expect("Cannot access system's clipboard");

    // Show all available commands
    print_help();

    loop {
        let sig = line_editor.read_line(&prompt);

        match sig {
            Ok(Signal::Success(input)) => {
                let parts: Vec<&str> = input.trim().split_whitespace().collect();
                if parts.is_empty() {
                    continue;
                }

                // Match command
                match parts[0] {
                    "new" => {
                        if parts.len() != 2 && parts.len() != 3 {
                            println!("Użycie: new <nazwa> lub new <nazwa> <długość>");
                            continue;
                        }
                        
                        // Check if this label isn't already used
                        let label = parts[1];
                        if vault.contains_key(label){
                            println!("Już istnieje hasło z tą etykietą!");
                            continue;
                        }

                        let len: usize;
                        if parts.len() == 3{
                            if let Ok(input) = parts[2].parse::<usize>(){
                                len = input;
                            } else{
                                println!("Długość hasła musi być dodatnią liczbą całkowitą!");
                                continue;
                            };
                            if len == 0{
                                println!("Długość hasła musi być dodatnią liczbą całkowitą!");
                                continue; 
                            }

                        } else{
                            len = DEFAULT_PASSWORD_LEN;
                        }

                        // Password generator
                        let password_generator = PasswordGenerator::new()
                            .length(len)
                            .lowercase_letters(true)
                            .uppercase_letters(true)
                            .symbols(true)
                            .strict(true);

                        // Generate random password and save it
                        let password: String;
                        match password_generator.generate_one() {
                            Ok(p) => {password = p}
                            Err(error) => {
                                println!("{}", error);
                                continue;
                            }
                        }

                        add_and_save_password(&mut vault, label, &password, &master_key);
                        println!("Hasło {} pomyślnie zapisane", label);

                        // Rebuild line editor to update completions (but it clears history)
                        line_editor = cli::bulid_line_editor(vault.keys().cloned().collect(), commands.clone());
                        
                    }
                    "add" => {
                        if parts.len() < 2 {
                            println!("Użycie: add <nazwa>");
                            continue;
                        }
                        
                        // Check if this label isn't already used
                        let label = parts[1];
                        if vault.contains_key(label){
                            println!("Już istnieje hasło z tą etykietą!");
                            continue;
                        }

                        let opt_password = password_input();
                        match opt_password{
                            Some(password) => {
                                add_and_save_password(&mut vault, label, &password, &master_key);
                                println!("Dodano hasło {}", label);
                            }
                            
                            _ => {println!("Powtórzone hasło musi być identyczne jak pierwsze!");}
                        }

                    }
                    "remove" => {
                        if parts.len() < 2 {
                            println!("Użycie: remove <nazwa>");
                            continue;
                        }

                        // Check if there is such password to remove
                        let label = parts[1];
                        if !vault.contains_key(label){
                            println!("Nie ma zapisanego hasła z taką etykietą");
                            continue;
                        }

                        // Ask for confirmation, 'T' confirms, anthing else cancels
                        print!("Czy na pewno chcesz usunąć hasło {}? Tej akcji nie można odwrócić. T/[N] ", label);
                        
                        io::stdout().flush().unwrap();
                        let mut input = String::new();
                        match io::stdin().read_line(&mut input) {
                            Ok(_) => {
                                // If confirmed
                                if input.trim() == "T" {

                                    // Here this label must exist, it was checked before
                                    let removed_password = get_password(label, &master_key).expect("Couldn't decrypt password");
                                    remove_password_and_save(&mut vault, label);
                                    println!("Usunięto hasło {}: {}", label, removed_password);
                                    
                                    // Rebuild line editor to update completions (but it clears history)
                                    line_editor = cli::bulid_line_editor(vault.keys().cloned().collect(), commands.clone());

                                } else {
                                    println!("Nie potwierdzono usunięcia");
                                }
                            }
                            Err(_) => println!("Błąd odczytu"),
                        }
                        
                    }
                    "get" => {
                        if parts.len() < 2 {
                            println!("Użycie: get <nazwa>");
                            continue;
                        }
                        let label = parts[1];
                        
                        // Get password or None if there is not such label saved
                        let password = get_password(label, &master_key);
                        match password{
                            Some(password) => {

                                // Copy password to clipboard
                                clipboard.set_contents(password).expect("Cannot access system's clipboard");
                                println!("Hasło skopiowane do schowka!");
                            }
                            None => {println!("Nie ma zapisanego hasła z taką etykietą");}
                        }

                    }
                    "change-password" => {
                        if parts.len() > 1{
                            println!("Nadmiarowy argument {}", parts[1]);
                            continue;
                        }
                        
                        // Ask for confirmation
                        print!("Czy na pewno chcesz zmienić główne hasło? T/[N] ");
                        
                        io::stdout().flush().unwrap();
                        let mut input = String::new();
                        match io::stdin().read_line(&mut input) {
                            Ok(_) => {
                                if input.trim() == "T" {
                                    // Get master key from new password or None if user didn't input it correctly
                                    let opt_new_master_key = change_password(&mut vault, &master_key);
                                    match opt_new_master_key {
                                        Some(new_master_key) => {
                                            // Password changed correctly
                                            master_key = new_master_key;
                                            println!("Nowe hasło ustawione!");
                                        }
                                        // None - user didn't correctly repeat the new password
                                        _ => {println!("Powtórzone hasło musi być identyczne jak pierwsze! Nie zmieniono hasła.");}
                                    }
                                } else {
                                    println!("Nie potwierdzono zmiany hasła");
                                }
                            }
                            Err(_) => println!("Błąd odczytu"),
                        }
                        
                    }
                    "help" => {
                        if parts.len() > 1{
                            println!("Nadmiarowy argument {}", parts[1]);
                        } else{
                            print_help()
                        }
                    }
                    "exit" => {
                        if parts.len() > 1{
                            println!("Nadmiarowy argument {}", parts[1]);
                        } else{
                            on_exit(&mut master_key, clipboard);
                            break;
                        }
                    }
                    _ => println!("Nieznana komenda: '{}'. Wpisz 'help'.", parts[0]),
                }
            }
            Ok(Signal::CtrlD) | Ok(Signal::CtrlC) => {
                on_exit(&mut master_key, clipboard);
                break;
            }
            _ => {}
        }
    }
}

fn print_help(){
    println!(
"Dostępne komendy:
    new <nazwa> - Wygeneruj losowe hasło z podaną etykietą. Opcjonalnie można też podać długość hasła.
    add <nazwa> - Dodaj nowe hasło z podaną etykietą.
    remove <nazwa> - Usuń hasło z podaną etykietą.
    get <nazwa> - Skopiuj do schowka hasło z podaną etykietą.
    change-password - Zmień główne hasło.
    help - Treść oczywista.
    exit - Wyjdź."
    );
}

/// Clear master_key and potential password in clipboard
fn on_exit(master_key: &mut [u8], mut clipboard: ClipboardContext){
    master_key.zeroize();
    clipboard.set_contents(String::from("")).expect("Cannot modify system's clipboard");
    println!("Zakończono");
}

/// Returns None is user didn't repeat the password correctly
fn password_input() -> Option<String>{
    print!("Podaj nowe hasło: ");
    io::stdout().flush().unwrap();
    let password = read_password().unwrap();

    print!("Powtórz hasło: ");
    io::stdout().flush().unwrap();
    let password_repeat = read_password().unwrap();

    if password == password_repeat{
        return Some(password);
    } else{
        return None;
    }
}

/// If user correctly inputs new password it changes encrytpion of all
/// passwords, verification token and returns new master_key (from new password).
/// If not, it doesn't change anything and returns None
fn change_password(vault: &mut Vault, master_key: & [u8]) -> Option<[u8; 32]> {
    if let Some(new_password) = password_input(){
        let salt = load_salt().expect("Error reading salt file");
        let new_master_key = derive_master_key(&new_password, &salt);
        
        // Decrypt all passwords and encrypt them with new password
        change_encryption_to_new_master_password(vault, master_key, &new_master_key);

        // need to also change it in auth
        create_verification_token(&new_master_key);

        Some(new_master_key)
    } else{
        None
    }
}