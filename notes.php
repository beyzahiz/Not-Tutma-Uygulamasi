<?php
session_start();
include ("baglanti.php"); // Veritabanı bağlantısı
// Not kaydedildi mi kontrol et
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['note'])) {
    $note = $_POST['note'];
    $key = 'gizli_anahtar123'; // Şifreleme anahtarı
    $iv = '1234567891011121';  // IV 16 karakter olmalı

    $encryptedNote = openssl_encrypt($note, 'AES-128-CTR', $key, 0, $iv);

    $stmt = $baglanti->prepare("INSERT INTO notes (user_id, note) VALUES (?, ?)");
    $stmt->bind_param("is", $_SESSION['user_id'], $encryptedNote);
    $stmt->execute();
    $stmt->close();
}

// Notları çek ve çöz
$user_id = $_SESSION['user_id'];
$key = 'gizli_anahtar123';
$iv = '1234567891011121';

$result = $baglanti->query("SELECT * FROM notes WHERE user_id = $user_id");

?>

<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Notlarım</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #f8f9fa;
            padding: 100px;
        }
        .note-card {
            background: white;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 15px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
        }
        .navbar {
            background-color: #ffffff;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .form-container {
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            padding: 2rem;
            margin-bottom: 2rem;
        }
        .btn-primary {
            background-color: #0d6efd;
            border: none;
            padding: 0.5rem 1.5rem;
        }
        .btn-primary:hover {
            background-color: #0b5ed7;
        }
    </style>
</head>
<body>
    <!-- Navbar -->
    <nav class="navbar navbar-expand-lg navbar-light fixed-top">
        <div class="container">
            <a class="navbar-brand" href="#"><i class="fas fa-sticky-note me-2"></i>Not Uygulaması</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="logout.php"><i class="fas fa-sign-out-alt me-1"></i>Çıkış Yap</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container">
        <div class="mb-4">
            <h2>Not Ekle</h2>
            <form method="post" action="" class="note-card">
                <div class="mb-3">
                    <textarea name="note" class="form-control" rows="4" required 
                              placeholder="Notunuzu buraya yazın..."></textarea>
                </div>
                <button type="submit" class="btn btn-primary">Notu Kaydet</button>
            </form>
        </div>

        <h2>Notlarınız</h2>
        <?php if ($result->num_rows == 0): ?>
            <div class="alert alert-info">Henüz not eklenmemiş.</div>
        <?php else: ?>
            <?php while ($row = $result->fetch_assoc()): 
                $decrypted = decryptNote($row['note'], $row['iv'], $_SESSION['user_id'], $_SESSION['email']);
            ?>
                <div class="note-card">
                    <?php echo nl2br(htmlspecialchars($decrypted)); ?>
                </div>
            <?php endwhile; ?>
        <?php endif; ?>
    </div>

    <!-- Bootstrap JS ve Popper.js -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
