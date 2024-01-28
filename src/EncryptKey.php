<?php

namespace NAL\Session;

use Error;
use Throwable;

trait EncryptKey
{
    /**
     * Generate or retrieve the encryption key for the current date.
     *
     * @return bool|string The generated or retrieved encryption key.
     * @throws Error If an error occurs during key generation.
     */
    private function generate(): bool|string
    {
        $currentDate = date('Y_m_d');

        $directory = __DIR__ . DIRECTORY_SEPARATOR . "encrypt_key" . DIRECTORY_SEPARATOR;

        $file = $directory . "{$currentDate}_encrypt_key.txt";

        try {
            if (!is_dir($directory)) {
                mkdir($directory, 0777, true);
            }

            if (file_exists($file)) {
                return file_get_contents($file);
            }

            $handle = fopen($file, 'c');
            if ($handle === false) {
                return file_get_contents($file);
            }

            flock($handle, LOCK_EX);

            $files = glob($directory . '*.txt');
            foreach ($files as $existingFile) {
                preg_match('/(\d{4}_\d{2}_\d{2})_encrypt_key\.txt/', $existingFile, $matches);

                if (!empty($matches) && isset($matches[1])) {
                    $fileDate = $matches[1];

                    if ($fileDate !== $currentDate) {
                        unlink($existingFile);
                    }
                }
            }

            $encryptionKey = bin2hex(random_bytes(32));
            fwrite($handle, $encryptionKey);

            flock($handle, LOCK_UN);
            fclose($handle);

            return $encryptionKey;
        } catch (Throwable $e) {
            throw new Error($e->getMessage());
        }
    }
}
