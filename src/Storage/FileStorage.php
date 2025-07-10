<?php

namespace CsrfToken\Storage;

/**
 * FileStorage is a simple file-based implementation of the CsrfStorageInterface.
 * It stores CSRF tokens and their associated payloads in JSON files.
 */
class FileStorage implements CsrfStorageInterface
{
    /**
     * Directory where CSRF token files are stored.
     * Each token is stored in a file named by its SHA-256 hash.
     *
     * @var string
     */
    private string $dir;

    /**
     * Constructor for the FileStorage class.
     *
     * @param string $dir The directory where CSRF token files will be stored.
     *                    It will be created if it does not exist.
     */
    // Initializes the storage directory and ensures it exists.
    // The directory is set to be writable only by the owner (0700 permissions).
    // The directory path is normalized to ensure it ends with a slash.
    // If the directory does not exist, it will be created with the specified permissions.
    public function __construct(string $dir)
    {
        $this->dir = rtrim($dir, '/') . '/';
        if (!is_dir($this->dir)) {
            mkdir($this->dir, 0700, true);
        }
    }

    /**
     * Store a CSRF token and its associated payload.
     *
     * @param string $key The CSRF token key (will be hashed).
     * @param array $payload The payload associated with the CSRF token.
     */
    // This method stores the CSRF token payload in a JSON file.
    // The file is named using the SHA-256 hash of the token key to ensure uniqueness.
    // The payload is encoded as JSON and written to the file.
    // If the file already exists, it will be overwritten.
    public function store(string $key, array $payload): void
    {
        file_put_contents($this->dir . hash('sha256', $key) . '.json', json_encode($payload));
    }

    /**
     * Fetch the payload associated with a CSRF token.
     *
     * @param string $key The CSRF token key (will be hashed).
     * @return array|null The payload if found, null otherwise.
     */
    // This method retrieves the CSRF token payload from the corresponding JSON file.
    // It checks if the file exists and reads its contents.
    // If the file does not exist, it returns null.
    // If the file exists, it decodes the JSON content and returns it as an associative array.
    // If the JSON decoding fails, it will return null.
    // The file is named using the SHA-256 hash of the token key to ensure uniqueness.
    // This allows for efficient storage and retrieval of CSRF token data.
    // The method returns null if the token is not found.
    // This is useful for validating CSRF tokens and retrieving their associated data.
    // The payload can include additional information such as user ID, timestamp, or any other relevant
    // data that was stored when the token was created.
    public function fetch(string $key): ?array
    {
        $path = $this->dir . hash('sha256', $key) . '.json';
        if (!file_exists($path)) return null;
        return json_decode(file_get_contents($path), true);
    }

    /**
     * Remove a CSRF token and its associated payload.
     *
     * @param string $key The CSRF token key (will be hashed).
     */
    // This method deletes the CSRF token file associated with the given key.
    // It constructs the file path using the SHA-256 hash of the token key.
    // If the file exists, it will be removed.
    // This is useful for cleaning up expired or invalid tokens.
    // It ensures that the storage does not retain unnecessary data, which can help manage disk space
    // and improve performance by reducing the number of files in the storage directory.
    // The method does not return any value.
    // It simply performs the deletion operation.
    // If the file does not exist, it will do nothing.
    public function remove(string $key): void
    {
        $path = $this->dir . hash('sha256', $key) . '.json';
        if (file_exists($path)) unlink($path);
    }
}
