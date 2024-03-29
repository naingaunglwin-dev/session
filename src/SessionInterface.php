<?php

namespace NAL\Session;

/**
 * Session Interface
 *
 * The SessionInterface defines methods to interact with session data. It provides functionality to set and get session
 * values, check for the existence of session data, retrieve all session data, manage flash messages, destroy specific
 * session items, and clear all session data.
 */
interface SessionInterface
{
    /**
     * Get Session Name
     *
     * @return string
     */
    public function getSessionName(): string;

    /**
     * Get Session sameSite
     *
     * @return string
     */
    public function getSameSite(): string;

    /**
     * Get Session timeOut
     *
     * @return int
     */
    public function getSessionTimeout(): int;
    /**
     * Set a session variable.
     *
     * @param mixed $key The key for the session variable.
     * @param mixed $value The value to be stored.
     */
    public function set(mixed $key, mixed $value): void;

    /**
     * Get a session variable.
     *
     * @param mixed $key The key of the session variable (optional).
     * @return mixed The value of the session variable, or null if not found.
     */
    public function get(mixed $key = null): mixed;

    /**
     * Get all session variables.
     *
     * @return array An array containing all session variables.
     */
    public function getAll(): array;

    /**
     * Set a flash message with the given key and value.
     *
     * @param string $key The key of the flash message.
     * @param mixed $value The value of the flash message.
     * @return void
     */
    public function setFlashMessage(string $key, mixed $value): void;

    /**
     * Retrieve and remove a flash message with the given key.
     *
     * This method retrieves the flash message corresponding to the provided key
     * from the internal storage and removes it. Subsequent calls to getFlash with
     * the same key will return null.
     *
     * @param string $key The key of the flash message to retrieve.
     * @return string|array|object|null The value of the flash message if found, or null if not found.
     */
    public function getFlashMessage(string $key): string|array|object|null;

    /**
     * Destroy a specific session variable.
     *
     * @param mixed $key The key of the session variable to destroy.
     */
    public function destroy(mixed $key): void;

    /**
     * Destroy all session variables and the session itself.
     */
    public function destroy_all(): void;

    /**
     * Restart the session, effectively destroying all variables and starting a new session.
     */
    public function restart(): void;

    /**
     * Check Session set with secure or not
     *
     * @return bool
     */
    public function isSecure(): bool;

    /**
     * Check Session set with httpOnly or not
     *
     * @return bool
     */
    public function isHttpOnly(): bool;
}
