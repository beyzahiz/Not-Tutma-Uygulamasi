<?php
session_start();
require 'baglanti.php'; // Veritabanı bağlantısı

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $email = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL);
    $password = $_POST['password'];

    if (!$email) {
        die('Geçerli bir e-posta giriniz.');
    }

    if (strlen($password) < 6) {
        die('Parola en az 6 karakter olmalıdır.');
    }

    // Kullanıcı zaten var mı kontrol et
    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->execute([$email]);
    if ($stmt->fetch()) {
        die('Bu e-posta zaten kayıtlı.');
    }

    // Parolayı hashle
    $passwordHash = password_hash($password, PASSWORD_DEFAULT);

    // Yeni kullanıcı ekle
    $stmt = $pdo->prepare("INSERT INTO users (email, password) VALUES (?, ?)");
    $stmt->execute([$email, $passwordHash]);

    // Oturum başlat
    $_SESSION['user_id'] = $pdo->lastInsertId();
    $_SESSION['email'] = $email;

    header("Location: notes.php");
    exit;
} else {
    header("Location: index.php");
    exit;
}
?>
