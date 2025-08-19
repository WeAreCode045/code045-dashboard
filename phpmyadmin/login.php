<?php
// phpmyadmin/login.php
$db = new SQLite3(__DIR__ . '/../db/database.sqlite');
$token = $_GET['token'] ?? '';
if (!$token) {
    header('Location: /phpmyadmin/');
    exit;
}
$row = $db->querySingle("SELECT ps.*, u.username, s.password FROM pma_sessions ps JOIN users u ON ps.user_id = u.id JOIN servers s ON ps.server_id = s.id WHERE ps.token = '$token' AND ps.expires_at > " . time()*1000, true);
if (!$row) {
    header('Location: /phpmyadmin/');
    exit;
}
// Token is valid, set session for phpMyAdmin
session_start();
$_SESSION['PMA_single_signon_user'] = $row['username'];
$_SESSION['PMA_single_signon_password'] = $row['password'];
// Invalidate token
$db->exec("DELETE FROM pma_sessions WHERE token = '$token'");
header('Location: /phpmyadmin/');
exit;
?>
