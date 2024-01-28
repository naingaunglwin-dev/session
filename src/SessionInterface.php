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
     * @return string|array|object|null The value of the session variable, or null if not found.
     */
    public function get(mixed $key = null): string|array|object|null;

    /**
     * Get all session variables.
     *
     * @return array An array containing all session variables.
     */
    public function all(): array;

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
}
