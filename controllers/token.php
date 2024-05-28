<?php

/**
 * Ask for a backup token.
 *
 * @param array{JWT: string, instance: string} $data
 * @return array{code: int, message: string}
 */
function token(array $data): array
{
    $status_code = 201;
    $message = '';


    if (!isset($data['JWT']) || !isset($data['instance'])) {
        $status_code = 400;
        $message = 'Bad Request';

        return [
            'code' => $status_code,
            'message' => $message
        ];
    }


    // read the backup_tokens.txt file and if lines are more than 10, return status code 429
    $backup_tokens = file('/home/status/backup_tokens.txt', FILE_IGNORE_NEW_LINES);
    if (count($backup_tokens) >= 10) {
        $status_code = 429;
        $message = 'Too Many Backup attempts';

        return [
            'code' => $status_code,
            'message' => $message
        ];
    }


    // Get the backup host JWT
    $backup_host_jwt = file_get_contents('/home/status/jwt.txt');

    if ($backup_host_jwt === false) {
        $status_code = 500;
        $message = 'Server Error while reading backup host JWT';

        return [
            'code' => $status_code,
            'message' => $message
        ];
    }

    // Create a backup token with the backup host JWT and the B2Host JWT + instance name
    $backup_token = openssl_encrypt($data['JWT'] . $data['instance'], 'AES-256-CBC', $backup_host_jwt);

    if ($backup_token === false) {
        $status_code = 500;
        $message = 'Server Error while creating backup token';

        return [
            'code' => $status_code,
            'message' => $message
        ];
    }

    // Append the backup token to the backup_tokens.txt file
    $backup_token_wrote = file_put_contents('/home/status/backup_tokens.txt', $backup_token . PHP_EOL, FILE_APPEND);

    if ($backup_token_wrote === false) {
        $status_code = 500;
        $message = 'Server Error while writing backup token';

        return [
            'code' => $status_code,
            'message' => $message
        ];
    }

    // Escape input to prevent shell injection
    $escapedUsername = escapeshellarg($data['instance']);
    $escapedPassword = escapeshellarg($backup_token);

    // Create a new user with a home directory and set the shell to nologin
    exec("sudo useradd -m -s /usr/sbin/nologin $escapedUsername");

    // Set the user password
    exec("echo '$escapedUsername:$escapedPassword' | sudo chpasswd");

    $message = [
        'password' => $backup_token
    ];

    return [
        'code' => $status_code,
        'message' => $message
    ];
}