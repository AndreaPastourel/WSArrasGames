<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
header('Content-Type: application/json');
?>



<?php


error_reporting(E_ALL);
ini_set('display_errors', 1);

header('Content-Type: application/json');
require 'config.php';

$method = $_SERVER['REQUEST_METHOD'];
$endpoint = isset($_GET['endpoint']) ? $_GET['endpoint'] : null;

function authenticate($pdo)
{
    $headers = apache_request_headers();
    if (!isset($headers['Authorization'])) {
        http_response_code(401);
        echo json_encode(["error" => "Missing API token "]);
        exit;
    }
    $token = str_replace("Bearer ", "", $headers['Authorization']);
    $stmt = $pdo->prepare("SELECT id FROM users WHERE api_token=?");
    $stmt->execute([$token]);
    return $stmt->fetchColumn() ?: false;
}


//User

if ($endpoint == 'login' && $method == 'POST') {
    $data = json_decode(file_get_contents("php://input"), true);

    if (!isset($data['username']) || !isset($data['password'])) {
        http_response_code(400);
        echo json_encode(["error" => "Missing username or password"]);
        exit;
    }

    $stmt = $pdo->prepare("SELECT id, password, api_token FROM users WHERE username = ?");
    $stmt->execute([$data['username']]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && password_verify($data['password'], $user['password'])) {
        // Si l'utilisateur n'a pas encore de token, on lui en génère un
        if (!$user['api_token']) {
            $newToken = bin2hex(random_bytes(32));
            $updateStmt = $pdo->prepare("UPDATE users SET api_token = ? WHERE id = ?");
            $updateStmt->execute([$newToken, $user['id']]);
            $user['api_token'] = $newToken;
        }

        echo json_encode(["success" => true, "api_token" => $user['api_token']]);
    } else {
        http_response_code(401);
        echo json_encode(["error" => "Invalid credentials"]);
    }
}


// Liste des forfaits
if ($endpoint == 'forfaits' && $method == 'GET') {
    $stmt = $pdo->query("SELECT id, name, description,price FROM packages");
    echo json_encode($stmt->fetchAll());
}

// Réserver un forfait
if ($endpoint == 'reservations' && $method == 'POST') {
    $user_id = authenticate($pdo); // ✅ Vérifie que l’utilisateur est bien authentifié
    if (!$user_id) exit;

    $data = json_decode(file_get_contents("php://input"), true);

    if (!isset($data['package_id']) || !isset($data['type_id'])) { // ✅ Vérifie que type_id est présent
        http_response_code(400);
        echo json_encode(["error" => "Missing package_id or type_id"]);
        exit;
    }

    // ✅ Insérer correctement package_id + type_id
    $stmt = $pdo->prepare("INSERT INTO reservations (user_id, package_id, type_id, status, code) VALUES (?, ?, ?, 'Free', ?)");
    $code = uniqid("RES-");
    $stmt->execute([$user_id, $data['package_id'], $data['type_id'], $code]);

    echo json_encode(["success" => true, "code" => $code]);
}



// Liste des types de forfaits
if ($endpoint == 'types' && $method == 'GET') {
    $stmt = $pdo->query("SELECT id, name FROM types");
    echo json_encode($stmt->fetchAll());
}

// Historique des réservations
if ($endpoint == 'reservations' && $method == 'GET') {
    $user_id = authenticate($pdo);


    if (!$user_id) exit;

    $stmt = $pdo->prepare("SELECT 
    reservations.id, 
    reservations.package_id, 
    reservations.type_id, 
    reservations.status, 
    reservations.code, 
    reservations.created, 
    packages.name AS package_name ,
    types.name AS type_name 
FROM reservations
INNER JOIN packages ON reservations.package_id = packages.id
INNER JOIN types ON reservations.type_id = types.id
WHERE reservations.user_id = ?");



    $stmt->execute([$user_id]);
    echo json_encode($stmt->fetchAll());
}
