<?php
session_start();
require 'baglanti.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Form gönderildiğinde burası çalışır
    $email = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL);
    $password = $_POST['password'];

    if (!$email) {
        $error = "Geçerli bir e-posta giriniz.";
    } else {
        // Kullanıcıyı bul
        $stmt = $pdo->prepare("SELECT id, password FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user['password'])) {
            // Giriş başarılı, oturumu başlat
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['email'] = $email;
            header("Location: notes.php");
            exit;
        } else {
            $error = "E-posta veya parola yanlış.";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8" />
    <title>Giriş Yap</title>
</head>
<body>
    <h2>Giriş Yap</h2>
    <?php if (!empty($error)) : ?>
        <p style="color:red;"><?php echo htmlspecialchars($error); ?></p>
    <?php endif; ?>
    <form action="login.php" method="POST">
        <label for="email">E-posta:</label><br>
        <input type="email" id="email" name="email" required value="<?php echo isset($email) ? htmlspecialchars($email) : ''; ?>"><br><br>

        <label for="password">Parola:</label><br>
        <input type="password" id="password" name="password" required><br><br>

        <button type="submit">Giriş Yap</button>
    </form>

    <p>Hesabın yok mu? <a href="index.php">Kayıt Ol</a></p>
</body>
</html>
