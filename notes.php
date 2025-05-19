<?php
session_start();
require 'baglanti.php';

// Giriş kontrolü
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

$user_id = $_SESSION['user_id'];

// Şifreleme için sabit anahtar (daha iyi yöntemler var, ama bu temel için yeterli)
define('SECRET_KEY', 'BuCokGizliVeUzunBirAnahtar123!'); // 256 bit'e tamamla

function encryptNote($plaintext) {
    $key = hash('sha256', SECRET_KEY, true);
    $iv = openssl_random_pseudo_bytes(16);
    $ciphertext = openssl_encrypt($plaintext, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    return ['ciphertext' => base64_encode($ciphertext), 'iv' => bin2hex($iv)];
}

function decryptNote($ciphertext_base64, $iv_hex) {
    $key = hash('sha256', SECRET_KEY, true);
    $iv = hex2bin($iv_hex);
    $ciphertext = base64_decode($ciphertext_base64);
    return openssl_decrypt($ciphertext, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
}

// Yeni not ekleme işlemi
if ($_SERVER['REQUEST_METHOD'] == 'POST' && !empty($_POST['note'])) {
    $note_text = $_POST['note'];
    $encrypted = encryptNote($note_text);
    
    $stmt = $pdo->prepare("INSERT INTO notes (user_id, note_text, iv) VALUES (?, ?, ?)");
    $stmt->execute([$user_id, $encrypted['ciphertext'], $encrypted['iv']]);
    header("Location: notes.php");
    exit;
}

// Kullanıcının notlarını çekme
$stmt = $pdo->prepare("SELECT id, note_text, iv, created_at FROM notes WHERE user_id = ? ORDER BY created_at DESC");
$stmt->execute([$user_id]);
$notes = $stmt->fetchAll();

?>

<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8" />
    <title>Notlarım</title>
</head>
<body>
    <h2>Hoşgeldiniz, <?php echo htmlspecialchars($_SESSION['email']); ?>!</h2>
    <a href="logout.php">Çıkış Yap</a>
    <h3>Yeni Not Ekle</h3>
    <form method="POST" action="notes.php">
        <textarea name="note" rows="4" cols="50" required></textarea><br><br>
        <button type="submit">Notu Kaydet</button>
    </form>
    
    <h3>Notlarınız</h3>
    <?php if (count($notes) == 0): ?>
        <p>Henüz notunuz yok.</p>
    <?php else: ?>
        <ul>
            <?php foreach ($notes as $note): ?>
                <li>
                    <?php echo nl2br(htmlspecialchars(decryptNote($note['note_text'], $note['iv']))); ?><br>
                    <small><i>Eklenme Tarihi: <?php echo $note['created_at']; ?></i></small>
                </li>
                <hr>
            <?php endforeach; ?>
        </ul>
    <?php endif; ?>
</body>
</html>
