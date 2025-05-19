<?php
session_start();
?>

<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8" />
    <title>Kayıt Ol</title>
</head>
<body>
    <h2>Kayıt Ol</h2>
    <form action="kayit.php" method="POST">
        <label for="email">E-posta:</label><br>
        <input type="email" id="email" name="email" required><br><br>

        <label for="password">Parola:</label><br>
        <input type="password" id="password" name="password" required minlength="6"><br><br>

        <button type="submit">Kayıt Ol</button>
    </form>

    <p>Zaten üyeysen <a href="login.php">Giriş Yap</a></p>
</body>
</html>

