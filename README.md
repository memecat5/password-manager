# Passman
Prosty menedżer haseł obsługiwany z konsoli.

## Użytkowanie
### Pierwsze włączenie
Przy pierwszym włączeniu musisz ustawić główne hasło, które będzie służyło do dostępu do aplikacji i szyfrowania zapisanych haseł.

### Dostępne komendy:
- `new <nazwa>` - Wygeneruj losowe hasło z podaną etykietą. Opcjonalnie można też podać długość hasła.
- `add <nazwa>` - Dodaj nowe hasło z podaną etykietą.
- `remove <nazwa>` - Usuń hasło z podaną etykietą.
- `get <nazwa>` - Skopiuj do schowka hasło z podaną etykietą.
- `change-password` - Zmień główne hasło.
- `help` - Wypisz dostępny komendy.
- `exit` - Wyjdź.

Używanie komendy `add` jest niezalecane, ponieważ losowo wygenerowane hasło będzie trudniej złamać, a i tak będzie zapisane, więc nie musi być możliwe do zapamiętania.

## Działanie
Wszystkie dane aplikacji (włącznie z zaszyfrowanymi hasłami) są zapisywane w folderze passman_data w systemowym folderze danych aplikacji (np. dla windowsa to User/AppData/Roaming). W pliku verify zapisywany jest losowy token zaszyfrowany naszym hasłem, służy do weryfikacji głównego hasła przy logowaniu. W pliku salt trzymamy salt do algorytmu Argon2, który służy do tworzenia klucza z naszego hasła głownego. W pliku vault trzymane są zaszyfrowane hasła wraz z Nonce - liczbami, które też służą do szyfrowania haseł. Manualne zmienianie tych plików spowoduje nieoczekiwane zachowanie aplikacji, ale nie pomoże w oczytaniu zapisanych haseł - do ich odszyfrowania potrzebne jest nasze główne hasło i nie ma do tego obejścia.

Hasła są każdorazowo odszyfrowywane kiedy zarządamy do nich dostępu - komendą get. Po wyłączeniu aplikacji klucz z naszego hasła głównego jest jawnie usuwany z pamięci, a zawartość schowka jest zerowana.

Nie ma żadnych zabezpieczeń dotyczących siły haseł, polegam tutaj na odpowiedzialności użytkownika.