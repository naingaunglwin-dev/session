<?php

declare(strict_types = 1);

namespace NAL\Session;

use InvalidArgumentException;

/**
 * Session Management Class
 *
 * The Session class provides an interface for managing session data, including setting and getting values,
 * checking for the existence of session data, handling flash messages, and destroying sessions.
 * It also handles session configuration and periodic session ID regeneration for enhanced security.
 */
class Session implements SessionInterface
{
    use EncryptKey;

    /**
     * @var string The name of the session.
     */
    private string $name;

    /**
     * @var bool Indicates whether the session should be secure (HTTPS only).
     */
    private bool $secure;

    /**
     * @var bool Indicates whether the session cookie should be HTTP only.
     */
    private bool $httpOnly;

    /**
     * @var string The SameSite attribute for the session cookie.
     */
    private string $sameSite;

    /**
     * @var int The session timeout in seconds.
     */
    private int $timeOut;

    /**
     * @var object An object representing the session configuration.
     */
    private object $session;

    /**
     * @var array An array to store global session data.
     */
    private array $global;

    /**
     * @var string Encrypt Key For Session
     */
    private $encryptKey;

    private array $flashes;

    /**
     * Session constructor.
     *
     * @param string $name The name of the session.
     * @param object|null $config The configuration object for the session. It should have the following properties:
     *                       - 'name' (string): The session name.
     *                       - 'secure' (bool): Indicates whether the session should be secure (HTTPS only).
     *                       - 'httpOnly' (bool): Indicates whether the session cookie should be HTTP only.
     *                       - 'sameSite' (string): The SameSite attribute for the session cookie.
     *                       - 'timeOut' (int): The session timeout in seconds.
     * @param bool $useThisName If true, consider `$name` as the first priority to use as the session name.
     */
    public function __construct(string $name, object $config = null, bool $useThisName = null)
    {
        if (empty($config)) {
            $config = (object) [
                'name'     => 'simple_php_session_lib',
                'secure'   => true,
                'httpOnly' => true,
                'sameSite' => 'Strict',
                'timeOut'  => 3600
            ];
        }

        $this->checkConfig($config);

        $this->session = $config;

        $this->store($name ?? 'simple_php_session_lib', $useThisName ?? false);

        if ($this->session_none()) {

            $this->config();

            session_start();

            $this->regenerate();
        }

        $this->setSession();

        $this->encryptKey = $this->generate();

        $this->flashes = [];
    }

    /**
     * Store session configuration settings.
     *
     * @param string $name The name of the session
     */
    private function store(string $name, bool $first = null): void
    {
        $first = $first ?? false;

        if ($first) {
            $this->name = $name;
        } else {
            $this->name = $this->session->name ?? $name;
        }

        $this->secure   = $this->session->secure ?? true;
        $this->httpOnly = $this->session->httpOnly ?? true;
        $this->sameSite = $this->session->sameSite ?? 'Strict';
        $this->timeOut  = $this->session->timeOut ?? 3600;
    }

    /**
     * @inheritDoc
     */
    public function set(mixed $key, mixed $value): void
    {
        $this->global[$key] = $this->encrypt($value);

        $this->updateGlobalSession();
    }

    /**
     * @inheritDoc
     */
    public function get(mixed $key = null): string|array|object|null
    {
        if (!$key) {
            $values = [];
            if (!empty($this->global)) {
                foreach ($this->global as $key => $value) {
                    $values[$key] = $this->decrypt($value);
                }
                return $values;
            }

            return null;
        }
        if (isset($this->global[$key])) {
            return $this->decrypt($this->global[$key]);
        }
        return null;
    }

    /**
     * @inheritDoc
     */
    public function all(): array
    {
        return $this->global;
    }

    /**
     * @inheritDoc
     */
    public function setFlashMessage(string $key, mixed $value): void
    {
        $session = new self('session_flash_data');
        $session->set($key, $value);
    }

    /**
     * @inheritDoc
     */
    public function getFlashMessage(string $key): string|array|null|object
    {
        $session = new self('session_flash_data');
        $data    = $session->get($key);

        $session->destroy($key);

        return $data;
    }

    /**
     * @inheritDoc
     */
    public function destroy(mixed $key): void
    {
        if (isset($this->global[$key])) {
            unset($this->global[$key]);
        }

        $this->updateGlobalSession();
    }

    /**
     * @inheritDoc
     */
    public function destroy_all(): void
    {
        session_destroy();

        $this->updateGlobalSession();
    }

    /**
     * @inheritDoc
     */
    public function restart(): void
    {
        $this->destroy_all();

        $this->updateGlobalSession();
    }

    /**
     * @inheritDoc
     */
    public function isSecure(): bool
    {
        return $this->secure === true;
    }

    /**
     * Configure session parameters like cookie settings and name.
     */
    private function config(): void
    {
        session_set_cookie_params([
            'secure'   => $this->secure,
            'httponly' => $this->httpOnly,
            'samesite' => $this->sameSite
        ]);

        session_name($this->name);
    }

    /**
     * Regenerate the session ID and update session token if timeout is reached.
     */
    private function regenerate(): void
    {
        $lastAccessTime = $_SESSION['last_access_time'] ?? 0;

        $elapsedTime = time() - $lastAccessTime;

        if ($elapsedTime > $this->timeOut) {
            session_regenerate_id(true);

            $_SESSION['last_access_time'] = time();
        }
    }

    /**
     * Retrieve session data and initialize global session array.
     */
    private function setSession(): void
    {
        $this->global = $_SESSION ?? [];
    }

    /**
     * Check if a session is currently active.
     *
     * @return bool True if no session is active, false otherwise.
     */
    private function session_none(): bool
    {
        return session_status() === PHP_SESSION_NONE;
    }

    /**
     * Update the global session data with the current state of the class's session data.
     */
    private function updateGlobalSession(): void
    {
        $_SESSION = $this->global;
    }

    /**
     * @param $data
     * @return string
     */
    private function encrypt($data): string
    {
        $cipher = 'aes-256-cbc';
        $iv_length = openssl_cipher_iv_length($cipher);
        $iv = openssl_random_pseudo_bytes($iv_length);

        $encrypted_data = openssl_encrypt(serialize($data), $cipher, $this->encryptKey, 0, $iv);

        return base64_encode($iv . $encrypted_data);
    }

    /**
     * @param $data
     * @return mixed
     */
    private function decrypt($data): mixed
    {
        $cipher = 'aes-256-cbc';
        $iv_length = openssl_cipher_iv_length($cipher);
        $iv = substr(base64_decode($data), 0, $iv_length);
        $encrypted_data = substr(base64_decode($data), $iv_length);

        return unserialize(openssl_decrypt($encrypted_data, $cipher, $this->encryptKey, 0, $iv));
    }

    /**
     * Check and validate the session configuration.
     *
     * @param object $config The session configuration object.
     *
     * @throws InvalidArgumentException If any validation fails.
     */
    private function checkConfig(object $config): void
    {
        if (isset($config->name) && gettype($config->name) !== 'string') {
            throw new InvalidArgumentException("Session name must be string type");
        }

        if (isset($config->secure) && gettype($config->secure) !== 'boolean') {
            throw new InvalidArgumentException("Secure flag must be boolean type");
        }

        if (isset($config->httpOnly) && gettype($config->httpOnly) !== 'boolean') {
            throw new InvalidArgumentException("httpOnly flag must be boolean type");
        }

        if (isset($config->sameSite) && gettype($config->sameSite) !== 'string') {
            throw new InvalidArgumentException("sameSite attribute must be string type");
        }

        if (isset($config->timeOut) && gettype($config->timeOut) !== 'integer') {
            throw new InvalidArgumentException("TimeOut must be integer type");
        }
    }
}
