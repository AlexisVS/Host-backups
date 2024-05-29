<?php

/**
 * Ask for a backup token.
 *
 * @param array{JWT: string, instance: string} $data
 * @return array{
 *   code: int,
 *   message: array{
 *     token: string,
 *     credentials: array{
 *         username: string,
 *         password: string
 * }}}
 * @throws Exception
 */
function token(array $data): array
{
    $status_code = 201;
    $message = '';

    if (!isset($data['JWT']) || !isset($data['instance'])) {
        throw new Exception('Bad Request', 400);
    }

    // read the backup_tokens.txt file and if lines are more than 10, return status code 429
    $backup_tokens = file('/home/status/backup_tokens.txt', FILE_IGNORE_NEW_LINES);
    if (count($backup_tokens) >= 10) {
        throw new Exception('Too Many Backup attempts', 429);
    }

    // Get the backup host JWT
    $backup_host_jwt = file_get_contents('/home/status/jwt.txt');
    if ($backup_host_jwt === false) {
        throw new Exception('Server Error while reading backup host JWT', 500);
    }

    // Create a backup token with the backup host JWT and the B2Host JWT + instance name
    $backup_token = openssl_encrypt($data['JWT'] . $data['instance'], 'AES-256-CBC', $backup_host_jwt);
    if ($backup_token === false) {
        throw new Exception('Server Error while creating backup token', 500);
    }

    // Append the backup token to the backup_tokens.txt file
    $backup_token_wrote = file_put_contents('/home/status/backup_tokens.txt', $backup_token . PHP_EOL, FILE_APPEND);
    if ($backup_token_wrote === false) {
        throw new Exception('Server Error while writing backup token', 500);
    }

    // Escape input to prevent shell injection
    $username = escapeshellarg($data['instance']);
    $password = escapeshellarg($backup_token);

    // Create a new user and set the shell to nologin
    exec("sudo useradd -s /usr/sbin/nologin $username");

    // Set the user password
    exec("echo '$username:$password' | sudo chpasswd");

    $message = [
        'token' => $backup_token,
        'credentials' => [
            'username' => $username,
            'password' => $password
        ],
    ];

    return [
        'code' => $status_code,
        'message' => $message
    ];
}