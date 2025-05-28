<?php
session_start();
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
include("baglanti.php");
$username_err="";
$email_err="";
$parola_err="";
$parolatkr_err="";
$calistirekle = false; // Varsayılan olarak false tanımla

if (isset($_POST["kaydet"])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("Geçersiz istek! CSRF token doğrulaması başarısız.");
    }
    // Kullanıcı adı doğrulama kısmı
    if (empty($_POST["kullaniciadi"])) {
        $username_err = "Kullanıcı adı boş geçilemez!";
    } 
    else if(strlen($_POST["kullaniciadi"]) < 6) {
        $username_err = "Kullanıcı adı en az 6 karakterden oluşmalıdır.";
    }
    else if (!preg_match('/^[a-z\d_]{5,20}$/i', $_POST["kullaniciadi"])) {
        $username_err = "Kullanıcı adı harflerden ve rakamlardan oluşmalıdır.";
    }

    // E-mail doğrulama
    if (empty($_POST["email"])) {
        $email_err = "E-mail boş geçilemez!";
    }
    else if (!filter_var($_POST["email"], FILTER_VALIDATE_EMAIL)) {
        $email_err = "Geçersiz e-mail formatı girdiniz!";
    }

    // Parola doğrulama
    if (empty($_POST["parola"])) {
        $parola_err = "Parola kısmı boş geçilemez!";
    }
    else if (strlen($_POST["parola"]) < 6) {
        $parola_err = "Parola en az 6 karakterden oluşmalıdır!";
    }

    // Parola tekrar doğrulama
    if (empty($_POST["parolatkr"])) {
        $parolatkr_err = "Parola tekrar kısmı boş geçilemez!";
    }
    else if ($_POST["parolatkr"] != $_POST["parola"]) {
        $parolatkr_err = "Parolalar birbirleriyle uyuşmuyor!";
    }

// Kayıt işlemi
if (empty($username_err) && empty($email_err) && empty($parola_err) && empty($parolatkr_err)) {
    $name = $_POST["kullaniciadi"];
    $email = $_POST["email"];
    $password = $_POST["parola"];
    $parolatkr = $_POST["parolatkr"];
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    // Kullanıcı adı veya e-mail veritabanında var mı kontrol et
    $kontrol = $baglanti->prepare("SELECT id FROM users WHERE kullanici_adi = ? OR email = ?");
    if ($kontrol) {
        $kontrol->bind_param("ss", $name, $email);
        $kontrol->execute();
        $kontrol->store_result();

        if ($kontrol->num_rows > 0) {
            echo '<div class="alert alert-warning" role="alert">Bu kullanıcı adı veya e-mail zaten kayıtlı.</div>';
            $kontrol->close();
        } else {
            $kontrol->close();

            // Veritabanına ekleme işlemi
            $stmt = $baglanti->prepare("INSERT INTO users (kullanici_adi, email, parola) VALUES (?, ?, ?)");
            if ($stmt) {
                $stmt->bind_param("sss", $name, $email, $hashed_password);
                $calistirekle = $stmt->execute();
                $stmt->close();
            } else {
                echo '<div class="alert alert-danger" role="alert">Veritabanına kayıt eklenirken bir hata oluştu.</div>';
            }
        }
    } else {
        echo '<div class="alert alert-danger" role="alert">Kayıt kontrolü sırasında bir hata oluştu.</div>';
    }
}

    
    // Hata mesajı veya başarılı işlem bildirimi
    if ($calistirekle) {
        unset($_SESSION['csrf_token']); // Token sıfırla
        header("Location: login.php");
        exit();
    } else {
        echo '<div class="alert alert-danger" role="alert">Kayıt sırasında bir hata oluştu. Lütfen bilgilerinizi gözden geçiriniz!</div>';
    }
    
    mysqli_close($baglanti);
}

?>

<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>UYE KAYİT</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
  </head>
  <body>
   <div class="container p-5">
     <div class="card p-5">
     <form action="kayit.php" method="POST">
     <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
     <div class="mb-3">
    <label for="exampleInputEmail1" class="form-label">Kullanıcı Adı</label>
    <input type="text" class="form-control <?php 
        if(!empty($username_err)) {
            echo 'is-invalid'; // Hata varsa kırmızı
        } 
    ?>" id="exampleInputEmail1" aria-describedby="emailHelp" name="kullaniciadi">
    <div id="validationServer03Feedback" class="invalid-feedback">
    <?php echo htmlspecialchars($username_err); ?>
    </div>
  </div>
  <div class="mb-3">
  <div class="mb-3">
    <label for="exampleInputEmail1" class="form-label">E-mail</label>
    <input type="text" class="form-control <?php 
        if(!empty($email_err)) {
            echo 'is-invalid'; // Hata varsa kırmızı
        } 
    ?>" id="exampleInputEmail1" aria-describedby="emailHelp" name="email">
    <div id="validationServer03Feedback" class="invalid-feedback">
    <?php echo htmlspecialchars($email_err); ?>
    </div>
</div>

  <div class="mb-3">
    <label for="exampleInputPassword1" class="form-label">Parola</label>
    <input type="password" class="form-control <?php 
        if(!empty($parola_err)) {
            echo 'is-invalid'; // Hata varsa kırmızı
        } 
    ?>" id="exampleInputPassword1" name="parola">
    <div id="validationServer03Feedback" class="invalid-feedback">
    <?php echo htmlspecialchars($parola_err); ?>
    </div>
  </div>
  <div class="mb-3">
    <label for="exampleInputPassword1" class="form-label">Parola Tekrar</label>
    <input type="password" class="form-control <?php 
        if(!empty($parolatkr_err)) {
            echo 'is-invalid'; // Hata varsa kırmızı
        } 
    ?>" id="exampleInputPassword1" name="parolatkr">
    <div id="validationServer03Feedback" class="invalid-feedback">
    <?php echo htmlspecialchars($parolatkr_err); ?>
    </div>
  </div>
  <button type="submit" name="kaydet" class="btn btn-primary">KAYDET</button>
</form>
     </div>
   </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
  </body>
</html>
