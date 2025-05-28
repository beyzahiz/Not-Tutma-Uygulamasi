<?php
session_start();
if (empty($_SESSION['csrf_token'])) {
  $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
include("baglanti.php");
$username_err = "";
$parola_err = "";

if (isset($_POST["giris"])) {
    // CSRF kontrolü
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("Geçersiz istek! CSRF doğrulaması başarısız.");
    }

    // Giriş verilerini doğrula
    if (empty($_POST["kullaniciadi"])) {
        $username_err = "Kullanıcı adı boş geçilemez!";
    }

    if (empty($_POST["parola"])) {
        $parola_err = "Parola kısmı boş geçilemez!";
    } else if (strlen($_POST["parola"]) < 6) {
        $parola_err = "Parola en az 6 karakterden oluşmalıdır!";
    }

    // Hatalar yoksa devam et
    if (empty($username_err) && empty($parola_err)) {
        $name = $_POST["kullaniciadi"];
        $password = $_POST["parola"];

        // Güvenli sorgu
        $stmt = $baglanti->prepare("SELECT id, kullanici_adi, email, parola FROM users WHERE kullanici_adi = ?");
        if ($stmt) {
            $stmt->bind_param("s", $name);
            $stmt->execute();
            $sonuc = $stmt->get_result();

            if ($sonuc->num_rows > 0) {
                $ilgilikayit = $sonuc->fetch_assoc();
                $db_password = $ilgilikayit["parola"];

                if (password_verify($password, $db_password)) {
                    $_SESSION["user_id"] = $ilgilikayit["id"];
                    $_SESSION["username"] = $ilgilikayit["kullanici_adi"];
                    $_SESSION["email"] = $ilgilikayit["email"];
                    unset($_SESSION['csrf_token']); // tokeni sıfırla
                    header("location: notes.php");
                    exit();
                } else {
                    echo '<div class="alert alert-danger" role="alert">Parola yanlış!</div>';
                }
            } else {
                echo '<div class="alert alert-danger" role="alert">Kullanıcı bulunamadı!</div>';
            }

            $stmt->close();
        } else {
            echo '<div class="alert alert-danger" role="alert">Sorgu hazırlanamadı.</div>';
        }
    }

    mysqli_close($baglanti);
}
?>


<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>UYE GİRİŞ</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
</head>
<body>
   <div class="container p-5">
     <div class="card p-5">
     <form action="login.php" method="POST">
     <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>"> 

     <div class="mb-3">
        <label for="exampleInputEmail1" class="form-label">Kullanıcı Adı</label>
        <input type="text" class="form-control <?php if (!empty($username_err)) { echo 'is-invalid'; } ?>"
       name="kullaniciadi"
       id="exampleInputEmail1"
       value="<?php echo isset($_POST['kullaniciadi']) ? htmlspecialchars($_POST['kullaniciadi']) : ''; ?>">

       <div id="validationServer03Feedback" class="invalid-feedback">
        <?php echo htmlspecialchars($username_err); ?>
      </div>

      </div>
      <div class="mb-3">
        <label for="exampleInputPassword1" class="form-label">Parola</label>
        <input type="password" class="form-control <?php if (!empty($parola_err)) { echo 'is-invalid'; } ?>" name="parola" id="exampleInputPassword1">
        <div id="validationServer03Feedback" class="invalid-feedback">
          <?php echo htmlspecialchars($parola_err); ?>
        </div>

      </div>
      <button type="submit" name="giris" class="btn btn-primary">GİRİŞ YAP</button>
      <p class="text-center mt-3">
        Hesabınız yok mu? <a href="kayit.php">Kayıt Ol</a>
      </p>
    </form>
     </div>
   </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
</body>
</html>