<?php
// Veritabanı bağlantı ayarları
$host = "localhost";
$dbname = "notlar";
$username = "root";   // Ampps'de genellikle root
$password = "";       // Ampps'de varsayılan şifre boş

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8mb4", $username, $password);
    // Hata modu aktif
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Veritabanı bağlantı hatası: " . $e->getMessage());
}
?>
