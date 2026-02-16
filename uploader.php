<?php

// Very simple upload/download page.
// - Stores files in the same folder as this script.
// - Accepts all file types (no extension/MIME checks).

$dir         = __DIR__;
$scriptName  = basename(__FILE__);
$status      = '';
$statusError = false;

function clean_name(string $name): string
{
    return trim(basename($name));
}

function unique_path(string $dir, string $filename): string
{
    $path = $dir . DIRECTORY_SEPARATOR . $filename;
    if (!file_exists($path)) {
        return $path;
    }

    $dot = strrpos($filename, '.');
    if ($dot === false) {
        $name = $filename;
        $ext  = '';
    } else {
        $name = substr($filename, 0, $dot);
        $ext  = substr($filename, $dot);
    }

    $i = 1;
    do {
        $candidate = $name . '_' . $i . $ext;
        $path      = $dir . DIRECTORY_SEPARATOR . $candidate;
        $i++;
    } while (file_exists($path));

    return $path;
}

// Download
if (isset($_GET['download'])) {
    $name = (string)$_GET['download'];

    if (strpos($name, '..') !== false || strpos($name, '/') !== false || strpos($name, '\\') !== false) {
        http_response_code(400);
        echo 'Invalid file name';
        exit;
    }

    $name = clean_name($name);
    $path = $dir . DIRECTORY_SEPARATOR . $name;

    if (!is_file($path) || !is_readable($path)) {
        http_response_code(404);
        echo 'File not found';
        exit;
    }

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . basename($path) . '"');
    header('Content-Length: ' . filesize($path));
    header('Cache-Control: no-cache');

    if (function_exists('ob_get_level')) {
        while (ob_get_level() > 0) {
            ob_end_clean();
        }
    }

    readfile($path);
    exit;
}

// Upload
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $file = $_FILES['file'];

    if (!isset($file['error']) || is_array($file['error'])) {
        $status      = 'Unexpected upload error.';
        $statusError = true;
    } elseif ($file['error'] !== UPLOAD_ERR_OK) {
        switch ($file['error']) {
            case UPLOAD_ERR_INI_SIZE:
            case UPLOAD_ERR_FORM_SIZE:
                $status = 'File too large (check PHP limits).';
                break;
            case UPLOAD_ERR_PARTIAL:
                $status = 'Upload was partial.';
                break;
            case UPLOAD_ERR_NO_FILE:
                $status = 'No file chosen.';
                break;
            default:
                $status = 'Upload error code: ' . (int)$file['error'];
        }
        $statusError = true;
    } else {
        $original = $file['name'] ?? 'file';
        $name     = clean_name($original);
        if ($name === '') {
            $name = 'file';
        }

        $target = unique_path($dir, $name);

        if (!is_uploaded_file($file['tmp_name'])) {
            $status      = 'Upload not accepted by PHP.';
            $statusError = true;
        } elseif (!move_uploaded_file($file['tmp_name'], $target)) {
            $status      = 'Could not save file.';
            $statusError = true;
        } else {
            $status      = 'Uploaded as ' . basename($target) . '.';
            $statusError = false;
        }
    }
}

// List files in this folder (excluding script itself and obvious system files)
$files = [];
foreach (scandir($dir) as $entry) {
    if ($entry === '.' || $entry === '..') {
        continue;
    }
    if ($entry === $scriptName) {
        continue;
    }
    if (strcasecmp($entry, 'Thumbs.db') === 0) {
        continue;
    }

    $full = $dir . DIRECTORY_SEPARATOR . $entry;
    if (is_file($full)) {
        $files[] = [
            'name' => $entry,
            'size' => filesize($full),
            'time' => filemtime($full),
        ];
    }
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Uploader</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        h1 {
            margin-bottom: 0.5em;
        }
        .panel {
            background-color: #ffffff;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 15px;
            margin-bottom: 20px;
            box-shadow: 0 1px 2px rgba(0,0,0,0.05);
        }
        .status {
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 15px;
        }
        .status.ok {
            background-color: #e6ffed;
            border: 1px solid #b5e7c5;
            color: #155724;
        }
        .status.error {
            background-color: #ffe6e6;
            border: 1px solid #f5b5b5;
            color: #721c24;
        }
        form {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            align-items: center;
        }
        input[type="file"] {
            max-width: 300px;
        }
        input[type="submit"] {
            padding: 6px 12px;
            border-radius: 4px;
            border: 1px solid #007bff;
            background-color: #007bff;
            color: #ffffff;
            cursor: pointer;
        }
        input[type="submit"]:hover {
            background-color: #0056b3;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 8px 10px;
            border-bottom: 1px solid #e0e0e0;
            text-align: left;
        }
        th {
            background-color: #fafafa;
        }
        .empty {
            color: #666;
            font-style: italic;
        }
    </style>
</head>
<body>

<h1>File uploader</h1>

<div class="panel">
    <?php if ($status !== ''): ?>
        <div class="status <?php echo $statusError ? 'error' : 'ok'; ?>">
            <?php echo htmlspecialchars($status, ENT_QUOTES, 'UTF-8'); ?>
        </div>
    <?php endif; ?>

    <h2>Upload a file</h2>
    <form method="post" enctype="multipart/form-data">
        <input type="file" name="file" required>
        <input type="submit" value="Upload">
    </form>
</div>

<div class="panel">
    <h2>Available files</h2>
    <?php if (empty($files)): ?>
        <p class="empty">No files yet.</p>
    <?php else: ?>
        <table>
            <thead>
            <tr>
                <th>Name</th>
                <th>Size (bytes)</th>
                <th>Last modified</th>
                <th>Action</th>
            </tr>
            </thead>
            <tbody>
            <?php foreach ($files as $f): ?>
                <tr>
                    <td><?php echo htmlspecialchars($f['name'], ENT_QUOTES, 'UTF-8'); ?></td>
                    <td><?php echo (int)$f['size']; ?></td>
                    <td><?php echo date('Y-m-d H:i:s', $f['time']); ?></td>
                    <td><a href="?download=<?php echo urlencode($f['name']); ?>">Download</a></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>

</body>
</html>

