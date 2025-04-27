# HTTP Digest Authentication Server — Assignment

## Student
**Альнсур Тарик Зохер Мохаммад**  
(Group 5140904/40102)

## Project Description
This project implements an HTTP server with **Digest Authentication** and uses an **SQLite** database to store user credentials.  
It is based on the assignment instructions:  
> Реализация аутентификации и авторизации пользователей на HTTP-сервере по схеме запрос-ответ (Digest-аутентификация HTTP) с использованием реляционной базы данных.

## Main Features
- **HTTP Digest Authentication** implemented according to RFC standards.
- **SQLite database (`users.db`)** stores users and their HA1 hashes (`username:realm:password` MD5).
- **OpenSSL** library is used to compute MD5 hashes.
- Correct password grants access; incorrect password returns `401 Unauthorized`.
- Server serves files from `webroot/` directory (e.g., `index.html`, `picture.png`).
- Logs HTTP requests to a local `foxweb.log` file.

## Technologies Used
- C (GCC compiler)
- OpenSSL (`libssl-dev`)
- SQLite3 (`libsqlite3-dev`)
- curl (for testing)

## How Authentication Works
1. Server responds with `401 Unauthorized` + Digest challenge.
2. Client calculates a response using username, password, nonce, cnonce, URI, and qop.
3. Server verifies the response using the stored HA1 hash.
4. If correct: server serves requested content.
5. If incorrect: server keeps sending `401 Unauthorized`.

## How to Run

### 1. Install required libraries
```bash
sudo apt-get update
sudo apt-get install libssl-dev libsqlite3-dev sqlite3
```

### 2. Build the server
```bash
make clean
make
```

### 3. Run the server
```bash
./PICOFoxweb 8080
```

Server will listen on:  
`http://127.0.0.1:8080/`

### 4. Default credentials
- **Username:** `admin`
- **Password:** `password123`

Stored in `users.db` inside the `users` table.



