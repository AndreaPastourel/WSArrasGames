<?php
$db = "lela3306_cake_arrasgames";
$dbhost = "localhost";
$dbport = 3306;
$dbuser = "lela3306_root";
$dbpassword = "`R00t895*";

try {
    $pdo = new PDO('mysql:host=' . $dbhost . ';port=' . $dbport . ';dbname=' . $db, $dbuser, $dbpassword);
    $pdo->exec("SET CHARACTER SET utf8");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Erreur de connexion : " . $e->getMessage());
}

$method = $_SERVER['REQUEST_METHOD'];
$request = isset($_SERVER['PATH_INFO']) ? explode('/', trim($_SERVER['PATH_INFO'], '/')) : [];
$endpoint = isset($_GET['endpoint']) ? $_GET['endpoint'] : null;
