<?php

namespace CsrfToken\Storage;

use PDO;

/**
 * MysqlStorage is a MySQL-based implementation of the CsrfStorageInterface.
 * It stores CSRF tokens and their associated payloads in a MySQL database.
 */
class MysqlStorage implements CsrfStorageInterface
{
    /**
     * @var PDO
     * The PDO instance used to interact with the MySQL database.
     * It should be initialized with a valid DSN, username, and password.
     */
    private PDO $pdo;

    /**
     * Constructor for the MysqlStorage class.
     *
     * @param PDO $pdo The PDO instance for database interactions.
     *                 It should be connected to a MySQL database with a table named 'csrf_cache'.
     *                 The table should have columns: token_hash (VARCHAR), payload (TEXT), created_at (DATETIME).
     */
    // Initializes the storage with a PDO instance.
    // The PDO instance should be connected to a MySQL database.
    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    /**
     * Store a CSRF token and its associated payload.
     *
     * @param string $key The CSRF token key (will be hashed).
     * @param array $payload The payload associated with the CSRF token.
     */
    // This method stores the CSRF token payload in the MySQL database.
    // It uses a prepared statement to prevent SQL injection.
    // The token is hashed using SHA-256 to ensure uniqueness.
    // The payload is stored as a JSON string in the 'payload' column.
    // If a token with the same hash already exists, it will be replaced.
    // The 'created_at' column is set to the current timestamp.
    // The table should have been created with the following SQL:
    // CREATE TABLE csrf_cache (
    //     token_hash VARCHAR(64) PRIMARY KEY,
    //     payload TEXT NOT NULL,
    //     created_at DATETIME NOT NULL
    // );
    // The 'token_hash' column is indexed for faster lookups.
    // The 'payload' column can store large JSON objects.
    // The 'created_at' column is used to track when the token was created.
    // This method does not return any value.
    // It will throw an exception if the database operation fails.
    public function store(string $key, array $payload): void
    {
        $stmt = $this->pdo->prepare("REPLACE INTO csrf_cache (token_hash, payload, created_at) VALUES (?, ?, NOW())");
        $stmt->execute([hash('sha256', $key), json_encode($payload)]);
    }


    /**
     * Fetch the payload associated with a CSRF token.
     *
     * @param string $key The CSRF token key (will be hashed).
     * @return array|null The payload if found, null otherwise.
     */
    // This method retrieves the CSRF token payload from the MySQL database.
    public function fetch(string $key): ?array
    {
        $stmt = $this->pdo->prepare("SELECT payload FROM csrf_cache WHERE token_hash = ?");
        $stmt->execute([hash('sha256', $key)]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ? json_decode($row['payload'], true) : null;
    }

    /**
     * Remove a CSRF token and its associated payload.
     *
     * @param string $key The CSRF token key (will be hashed).
     */
    // This method removes a CSRF token from the MySQL database.
    public function remove(string $key): void
    {
        $stmt = $this->pdo->prepare("DELETE FROM csrf_cache WHERE token_hash = ?");
        $stmt->execute([hash('sha256', $key)]);
    }
}
