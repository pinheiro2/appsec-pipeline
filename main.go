package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	_ "modernc.org/sqlite"
)

func getJWTSecret() string {
    secret := os.Getenv("JWT_SECRET")
    if secret == "" {
        log.Fatal("SECURITY ERROR: JWT_SECRET environment variable is not set. Service refusing to start.")
    }
    return secret
}


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

	secureQuery := "SELECT id, username, email, role, balance FROM users WHERE username = ?"

	
	rows, err := db.Query(secureQuery, queryUser)
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

func getUserProfileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Simulated authentication: headers "X-User-Role" and "X-User-Id"
	roleHeader := r.Header.Get("X-User-Role")
	callerID := r.Header.Get("X-User-Id") // Represents the ID from a verified JWT
	
	if roleHeader == "" || callerID == "" {
		http.Error(w, "Unauthorized: missing authentication headers", http.StatusUnauthorized)
		return
	}

	requestedUserID := r.URL.Query().Get("id")
	if requestedUserID == "" {
		http.Error(w, "Query param 'id' is required", http.StatusBadRequest)
		return
	}

	// SECURE: The BOLA / IDOR Fix
	// If you are not an admin, you can only access the ID that matches your own callerID
	if roleHeader != "admin" && callerID != requestedUserID {
		http.Error(w, "Forbidden: you do not have permission to access this profile", http.StatusForbidden)
		return
	}

	var u User
	err := db.QueryRow("SELECT id, username, email, role, balance FROM users WHERE id = ?", requestedUserID).
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
	jwtSecret := getJWTSecret()
    _ = jwtSecret
	
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