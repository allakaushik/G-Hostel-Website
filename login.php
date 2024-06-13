<?php
session_start();
$servername = "localhost"; // Replace with your database server details
$username = "root"; // Replace with your database username
$password = ""; // Replace with your database password
$dbname = "your_database_name"; // Replace with your database name

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if (isset($_POST['signup'])) {
    $reg_number = $_POST['reg_number'];
    $email = $_POST['email'];
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];

    if ($password !== $confirm_password) {
        echo "Passwords do not match!";
        exit;
    }

    $hashed_password = password_hash($password, PASSWORD_BCRYPT);

    $stmt = $conn->prepare("INSERT INTO users (registration_number, email, password) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $reg_number, $email, $hashed_password);

    if ($stmt->execute()) {
        header("Location: home.html");
    } else {
        echo "Error: " . $stmt->error;
    }

    $stmt->close();
}

if (isset($_POST['signin'])) {
    $email = $_POST['email'];
    $password = $_POST['password'];

    $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 1) {
        $user = $result->fetch_assoc();

        if (password_verify($password, $user['password'])) {
            $_SESSION['user_id'] = $user['id'];
            header("Location: home.html");
        } else {
            echo "Invalid password!";
        }
    } else {
        echo "No user found with that email address!";
    }

    $stmt->close();
}

$conn->close();
?>
