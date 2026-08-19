package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	_ "modernc.org/sqlite"
)

// Vulnerability 1: Hardcoded sensitive secret / JWT signing key (OWASP A07 / CWE-798)
const HardcodedJWTSecret = "SuperSecretAdminKey12345!@#"

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	Balance  int    `json:"balance"`
}

var db *sql.DB

func initDB() {
	var err error
	db, err = sql.Open("sqlite", "file::memory:?cache=shared")
	if err != nil {
		log.Fatalf("Failed to open DB: %v", err)
	}

	createTable := `
	CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT,
		password TEXT,
		email TEXT,
		role TEXT,
		balance INTEGER
	);`
	if _, err := db.Exec(createTable); err != nil {
		log.Fatalf("Failed to create table: %v", err)
	}

	// Seed dummy records
	seedData := `
	INSERT INTO users (username, password, email, role, balance) VALUES
	('alice', 'plaintext_alice_pw', 'alice@corp.local', 'user', 500),
	('bob', 'plaintext_bob_pw', 'bob@corp.local', 'user', 250),
	('admin', 'admin_secret_pass', 'admin@corp.local', 'admin', 99999);`
	if _, err := db.Exec(seedData); err != nil {
		log.Fatalf("Failed to seed DB: %v", err)
	}
}

// Vulnerability 2: SQL Injection via string concatenation (OWASP A03 / CWE-89)
// Endpoint: GET /api/users/search?username=...
func searchUsersHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	queryUser := r.URL.Query().Get("username")
	if queryUser == "" {
		http.Error(w, "Query param 'username' is required", http.StatusBadRequest)
		return
	}

	// VULNERABLE: Direct string formatting into SQL query
	rawQuery := fmt.Sprintf("SELECT id, username, email, role, balance FROM users WHERE username = '%s'", queryUser)
	
	rows, err := db.Query(rawQuery)
	if err != nil {
		http.Error(w, fmt.Sprintf("Database query error: %v", err), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var results []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.Balance); err != nil {
			http.Error(w, "Scan error", http.StatusInternalServerError)
			return
		}
		results = append(results, u)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// Vulnerability 3: Broken Object Level Authorization (BOLA/IDOR) (OWASP A01 / CWE-639)
// Endpoint: GET /api/user/profile?id=...
func getUserProfileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Simulated authentication: header "X-User-Role"
	roleHeader := r.Header.Get("X-User-Role")
	if roleHeader == "" {
		http.Error(w, "Unauthorized: missing X-User-Role header", http.StatusUnauthorized)
		return
	}

	userID := r.URL.Query().Get("id")
	if userID == "" {
		http.Error(w, "Query param 'id' is required", http.StatusBadRequest)
		return
	}

	// VULNERABLE: Although parameterized, it lacks object-level authorization checks.
	// Any authenticated user can read any other user's full balance and data simply by enumerating ?id=
	var u User
	err := db.QueryRow("SELECT id, username, email, role, balance FROM users WHERE id = ?", userID).
		Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.Balance)

	if err == sql.ErrNoRows {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(u)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy"}`))
}

func main() {
	initDB()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/api/users/search", searchUsersHandler)
	mux.HandleFunc("/api/user/profile", getUserProfileHandler)

	addr := ":8080"
	log.Printf("Starting intentionally vulnerable API on %s ...", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}