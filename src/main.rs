mod auth;
mod password_storage;

use std::io::{self, Write};
use clipboard::{ClipboardProvider, ClipboardContext};
use reedline::{default_emacs_keybindings, ColumnarMenu, Completer, Emacs, KeyCode, KeyModifiers, MenuBuilder, Reedline, ReedlineEvent, ReedlineMenu};
use reedline::{Signal, DefaultPrompt, Span, Suggestion};
use rpassword::read_password;
use zeroize::Zeroize;
use crate::auth::*;
use crate::password_storage::*;


fn main() {
    // Check if master password is set
    let mut master_key = if !master_password_exists() {
        // Set new master password
        println!("Nie znaleziono profilu.");
        let password: String;
        loop{
            let opt_password = set_new_password();

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
    //let mut labels = vec![];
    let commands = vec![
        String::from("new"),
        String::from("remove"),
        String::from("get"),
        String::from("change-password"),
        String::from("help"),
        String::from("exit")
        ];


    let prompt = DefaultPrompt::default();

    let mut line_editor = bulid_line_editor(vault.keys().cloned().collect(), commands.clone());

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

                match parts[0] {
                    "new" => {
                        if parts.len() < 2 {
                            println!("Użycie: new <nazwa>");
                        } else {
                            let label = parts[1];
                            let password = generate_random_password();
                            add_and_save_password(&mut vault, label, &password, &master_key);
                            println!("Hasło {} pomyślnie zapisane", label);

                            line_editor = bulid_line_editor(vault.keys().cloned().collect(), commands.clone());
                        }
                    }
                    "remove" => {
                        if parts.len() < 2 {
                            println!("Użycie: remove <nazwa>");
                        } else {
                            let label = parts[1];
                            print!("Czy na pewno chcesz usunąć hasło {}? Tej akcji nie można odwrócić. T/[N] ", label);
                            
                            io::stdout().flush().unwrap();
                            let mut input = String::new();
                            match io::stdin().read_line(&mut input) {
                                Ok(_) => {
                                    if input.trim() == "T" {
                                        remove_password_and_save(&mut vault, label);
                                        println!("Hasło {} usunięte", label);
                                        
                                        // Rebuild line_editor with updated completions
                                        line_editor = bulid_line_editor(vault.keys().cloned().collect(), commands.clone());

                                    } else {
                                        println!("Nie potwierdzono usunięcia");
                                    }
                                }
                                Err(_) => println!("Błąd odczytu"),
                            }
                        }
                    }
                    "get" => {
                        if parts.len() < 2 {
                            println!("Użycie: get <nazwa>");
                        } else {
                            let label = parts[1];
                            
                            let password = get_password(label, &master_key);
                            match password{
                                Some(password) => {
                                    let mut clipboard: ClipboardContext = ClipboardProvider::new().expect("Cannot access system's clipboard");
                                    clipboard.set_contents(password).expect("Cannot access system's clipboard");

                                    println!("Hasło skopiowane do schowka!");
                                }
                                None => {println!("Nie ma zapisanego hasła z taką etykietą");}
                            }

                        }
                    }
                    "change-password" => {
                        if parts.len() > 1{
                            println!("Nadmiarowy argument {}", parts[1]);
                        } else{
                            print!("Czy na pewno chcesz zmienić główne hasło? T/[N] ");
                            
                            io::stdout().flush().unwrap();
                            let mut input = String::new();
                            match io::stdin().read_line(&mut input) {
                                Ok(_) => {
                                    if input.trim() == "T" {
                                        if let Some(new_password) = set_new_password(){
                                            let salt = load_salt().expect("Error reading salt file");
                                            let new_master_key = derive_master_key(&new_password, &salt);

                                            // Decrypt all passwords and encrypt them with new password
                                            
                                            // need to also change it in auth
                                            //change_master_password(&mut vault, &master_key, &new_master_key);

                                            // Why does this work when new is not mut?
                                            master_key = new_master_key;

                                        } else{
                                            println!("Powtórzone hasło musi być identyczne jak pierwsze! Nie zmieniono hasła.");
                                        }

                                    } else {
                                        println!("Nie potwierdzono zmiany hasła");
                                    }
                                }
                                Err(_) => println!("Błąd odczytu"),
                            }
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
                            // Clear master_key from memory
                            on_exit(&mut master_key);
                            break;
                        }
                    }
                    _ => println!("Nieznana komenda: '{}'. Wpisz 'help'.", parts[0]),
                }
            }
            Ok(Signal::CtrlD) | Ok(Signal::CtrlC) => {
                // Clear master_key from memory
                on_exit(&mut master_key);
                break;
            }
            _ => {}
        }
    }
}

fn print_help(){
    println!(
"Dostępne komendy:
    new <nazwa> - dodaj nowe hasło z podaną etykietą
    remove <nazwa> - usuń hasło z podaną etykietą
    get <nazwa> - skopiuj do schowka hasło z podaną etykietą
    change-password - zmień główne hasło
    help - treść oczywista
    exit - wyjdź"
    );
}

fn on_exit(master_key: &mut [u8]){
    master_key.zeroize();
    println!("Zakończono");
}

/// Returns None is user didn't repeat the password correctly
fn set_new_password() -> Option<String>{
    print!("Stwórz nowe hasło: ");
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

// Custom completer to handle commands and optional labels
struct CommandAndLabelCompleter {
    commands: Vec<String>,
    labels: Vec<String>,
}

impl Completer for CommandAndLabelCompleter {
    fn complete(&mut self, line: &str, pos: usize) -> Vec<Suggestion> {
        
        // Split input in parts - one (just command) or two (command and label)
        let input = &line[..pos];
        let parts: Vec<&str> = input.split_whitespace().collect();
        
        // Determine what we're completing
        let (completing_word, word_start) = if input.ends_with(' ') {
            // Starting a label for get/remove
            ("", pos)
        } else if parts.len() == 2 {
            // Completing a label for get/remove
            (parts[1], parts[0].len()+1)
        } else {
            // Completing of starting a command
            (input, 0)
        };

        let mut suggestions = Vec::new();

        if parts.is_empty() || (parts.len() == 1 && !input.ends_with(' ')) {
            // Complete command
            for cmd in &self.commands {
                if cmd.starts_with(completing_word) {

                    // Add whitespace to the suggestion if we expect a second argument
                    if cmd == "get" || cmd == "remove" || cmd == "new"{
                        suggestions.push(Suggestion {
                            value: cmd.clone(),
                            description: None,
                            extra: None,
                            style: None,
                            span: Span {
                                start: word_start,
                                end: pos,
                            },
                            append_whitespace: true,
                        });
                    } else{
                        suggestions.push(Suggestion {
                            value: cmd.clone(),
                            description: None,
                            extra: None,
                            style: None,
                            span: Span {
                                start: word_start,
                                end: pos,
                            },
                            append_whitespace: false,
                        });
                    }
                }
            }
        } else if parts.len() >= 1 {
            // Complete label for get and remove
            let command = parts[0];
            if command == "get" || command == "remove" {
                for label in &self.labels {
                    if label.starts_with(completing_word) {
                        suggestions.push(Suggestion {
                            value: label.clone(),
                            description: None,
                            extra: None,
                            style: None,
                            span: Span {
                                start: word_start,
                                end: pos,
                            },
                            append_whitespace: false,
                        });
                    }
                }
            }
        }

        return suggestions;
    }
}

/// Constumes both parameters, they must be cloned
fn bulid_line_editor(labels: Vec<String>, commands: Vec<String>) -> Reedline{

    let completer = Box::new(CommandAndLabelCompleter{commands: commands, labels: labels});
    // Use the interactive menu to select options from the completer
    let completion_menu = Box::new(ColumnarMenu::default().with_name("completion_menu"));
    // Set up the required keybindings
    let mut keybindings = default_emacs_keybindings();
    keybindings.add_binding(
        KeyModifiers::NONE,
        KeyCode::Tab,
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu("completion_menu".to_string()),
            ReedlineEvent::MenuNext,
        ]),
    );

    let edit_mode = Box::new(Emacs::new(keybindings));

    return Reedline::create()
        .with_completer(completer)
        .with_menu(ReedlineMenu::EngineCompleter(completion_menu))
        .with_edit_mode(edit_mode);
}