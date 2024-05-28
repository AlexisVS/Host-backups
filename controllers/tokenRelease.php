<?php

/**
 * Release the token of a given instance.
 *
 *
 * @param array{JWT: string, instance: string} $data
 * @return array{code: int, message: string}
 */

function tokenRelease(array $data): array
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

    // Remove the token from the backup_tokens.txt file
    $backup_tokens = file('/home/status/backup_tokens.txt', FILE_IGNORE_NEW_LINES);
    $backup_tokens = array_diff($backup_tokens, [$backup_token]);
    $backup_token_wrote = file_put_contents('/home/status/backup_tokens.txt', implode("\n", $backup_tokens));

    if ($backup_token_wrote === false) {
        $status_code = 500;
        $message = 'Server Error while writing backup token';

        return [
            'code' => $status_code,
            'message' => $message
        ];
    }

    $message = 'Token released';

    return [
        'code' => $status_code,
        'message' => $message
    ];
}