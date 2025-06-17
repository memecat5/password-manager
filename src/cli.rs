use reedline::{default_emacs_keybindings, ColumnarMenu, Completer, Emacs, KeyCode,
    KeyModifiers, MenuBuilder, Reedline, ReedlineEvent, ReedlineMenu, Span, Suggestion};

// Custom completer to handle commands and optional labels
pub struct CommandAndLabelCompleter {
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
pub fn bulid_line_editor(labels: Vec<String>, commands: Vec<String>) -> Reedline{

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