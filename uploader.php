<?php
// Simple file upload/download manager
// Files are stored in the same directory as this script (__DIR__).
//
// Windows / php.ini notes:
// - Ensure `file_uploads = On`
// - Increase `upload_max_filesize` and `post_max_size` if you need large uploads
// - `max_file_uploads` controls how many files can be uploaded at once
//
// This script intentionally accepts all file types and does not restrict
// extensions or MIME types. It still keeps operations limited to this directory.

// ----------------------------
// Configuration
// ----------------------------

// Optional: uncomment and adjust if you want to override limits at runtime.
// @ini_set('upload_max_filesize', '100M');
// @ini_set('post_max_size', '100M');

$statusMessage = '';
$statusIsError = false;

$scriptName = basename(__FILE__);
$baseDir    = __DIR__;

// ----------------------------
// Helper: sanitize filename (allow simple names only)
// ----------------------------
function sanitize_filename(string $name): string
{
    // Remove any path components
    $name = basename($name);

    // Optionally trim control characters/whitespace
    $name = trim($name);

    return $name;
}

// ----------------------------
// Helper: generate collision-free path
// ----------------------------
function unique_target_path(string $dir, string $filename): string
{
    $target = $dir . DIRECTORY_SEPARATOR . $filename;
    if (!file_exists($target)) {
        return $target;
    }

    $dotPos = strrpos($filename, '.');
    if ($dotPos === false) {
        $name = $filename;
        $ext  = '';
    } else {
        $name = substr($filename, 0, $dotPos);
        $ext  = substr($filename, $dotPos); // includes the dot
    }

    $counter = 1;
    do {
        $candidate = $name . '_' . $counter . $ext;
        $target    = $dir . DIRECTORY_SEPARATOR . $candidate;
        $counter++;
    } while (file_exists($target));

    return $target;
}

// ----------------------------
// Download handling
// ----------------------------
if (isset($_GET['download'])) {
    $requested = $_GET['download'];

    // Basic validation to prevent directory traversal
    if (strpos($requested, '..') !== false || strpos($requested, '/') !== false || strpos($requested, '\\') !== false) {
        http_response_code(400);
        echo 'Invalid file name.';
        exit;
    }

    $requested = sanitize_filename($requested);
    $path      = $baseDir . DIRECTORY_SEPARATOR . $requested;

    if (!is_file($path) || !is_readable($path)) {
        http_response_code(404);
        echo 'File not found.';
        exit;
    }

    // Send file for download
    $filesize = filesize($path);

    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . rawbasename($path) . '"');
    header('Content-Length: ' . $filesize);
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Expires: 0');

    // Clean output buffer if any
    if (function_exists('ob_get_level')) {
        while (ob_get_level() > 0) {
            ob_end_clean();
        }
    }

    readfile($path);
    exit;
}

// Helper because PHP lacks rawbasename()
function rawbasename(string $path): string
{
    $base = basename($path);
    // Ensure it's safe for header; rawurlencode could be used in more complex cases
    return $base;
}

// ----------------------------
// Upload handling
// ----------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $file = $_FILES['file'];

    if (!isset($file['error']) || is_array($file['error'])) {
        $statusMessage = 'Unexpected upload error.';
        $statusIsError = true;
    } elseif ($file['error'] !== UPLOAD_ERR_OK) {
        switch ($file['error']) {
            case UPLOAD_ERR_INI_SIZE:
            case UPLOAD_ERR_FORM_SIZE:
                $statusMessage = 'File is too large (check upload_max_filesize/post_max_size).';
                break;
            case UPLOAD_ERR_PARTIAL:
                $statusMessage = 'File was only partially uploaded.';
                break;
            case UPLOAD_ERR_NO_FILE:
                $statusMessage = 'No file was uploaded.';
                break;
            default:
                $statusMessage = 'Unknown upload error code: ' . (int)$file['error'];
        }
        $statusIsError = true;
    } else {
        $originalName = $file['name'] ?? 'uploaded_file';
        $safeName     = sanitize_filename($originalName);

        if ($safeName === '') {
            $safeName = 'uploaded_file';
        }

        $targetPath = unique_target_path($baseDir, $safeName);

        if (!is_uploaded_file($file['tmp_name'])) {
            $statusMessage = 'Possible file upload attack detected.';
            $statusIsError = true;
        } elseif (!move_uploaded_file($file['tmp_name'], $targetPath)) {
            $statusMessage = 'Failed to move uploaded file.';
            $statusIsError = true;
        } else {
            $statusMessage = 'File uploaded successfully as ' . basename($targetPath) . '.';
            $statusIsError = false;
        }
    }
}

// ----------------------------
// Directory listing
// ----------------------------
$files = [];
foreach (scandir($baseDir) as $entry) {
    if ($entry === '.' || $entry === '..') {
        continue;
    }
    if ($entry === $scriptName) {
        continue;
    }
    // Skip obvious system files if you want
    if (strcasecmp($entry, 'Thumbs.db') === 0) {
        continue;
    }

    $fullPath = $baseDir . DIRECTORY_SEPARATOR . $entry;
    if (is_file($fullPath)) {
        $files[] = [
            'name' => $entry,
            'size' => filesize($fullPath),
            'time' => filemtime($fullPath),
        ];
    }
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Simple File Upload/Download</title>
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

<h1>Simple File Upload/Download</h1>

<div class="panel">
    <?php if ($statusMessage !== ''): ?>
        <div class="status <?php echo $statusIsError ? 'error' : 'ok'; ?>">
            <?php echo htmlspecialchars($statusMessage, ENT_QUOTES, 'UTF-8'); ?>
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
        <p class="empty">No files in this directory yet (besides the script itself).</p>
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

