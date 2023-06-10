<?php
$DATABASE_HOST = 'localhost';
$DATABASE_USER = 'root';
$DATABASE_PASS = '';
$DATABASE_NAME = 'Scania';

// Create connection
$con = mysqli_connect($DATABASE_HOST, $DATABASE_USER, $DATABASE_PASS, $DATABASE_NAME);
// Check connection
if (mysqli_connect_errno()) {
    exit('Failed to connect to MySQL: ' . mysqli_connect_error());
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Collect form data
    $username = $_POST['username'];
    $password = $_POST['password'];
    $email = $_POST['email'];

    // Validate form data
    if (empty($username) || empty($password) || empty($email)) {
        exit('Please complete the registration form');
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        exit('Email is not valid!');
    }

    if (strlen($password) > 16 || strlen($password) < 5) {
        exit('Password must be between 5 and 16 characters long!');
    }

    $stmt = $con->prepare('SELECT id FROM register WHERE username = ? LIMIT 1');
    $stmt->bind_param('s', $username);
    $stmt->execute();
    $stmt->store_result();
    if ($stmt->num_rows > 0) {
        exit('Username exists, please choose another!');
    }

    $stmt = $con->prepare('INSERT INTO register (username, password, email) VALUES (?, ?, ?)');
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
    $stmt->bind_param('sss', $username, $hashed_password, $email);
    if ($stmt->execute()) {
        echo 'You have successfully registered! You can now login!';
    } else {
        echo 'Could not register. Please try again.';
    }
}
?>

