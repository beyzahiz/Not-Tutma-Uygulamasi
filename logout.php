<?php
session_start();
$_SESSİON=array();
session_destroy();
header("location:login.php");
?>