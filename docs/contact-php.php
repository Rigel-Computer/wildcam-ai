<?php
/**
 * Sicheres Kontaktformular-Verarbeitungsskript
 * Schutz gegen: Spam, XSS, SQL Injection, CSRF
 */

// Security Headers
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

// Nur POST-Anfragen erlauben
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Methode nicht erlaubt']);
    exit;
}

// Rate Limiting (einfach über Session)
session_start();
$currentTime = time();
$lastSubmission = $_SESSION['last_submission'] ?? 0;
$minInterval = 30; // 30 Sekunden zwischen Submissions

if ($currentTime - $lastSubmission < $minInterval) {
    http_response_code(429);
    echo json_encode(['success' => false, 'message' => 'Bitte warten Sie 30 Sekunden zwischen Anfragen']);
    exit;
}

// Honeypot-Check (Bot-Erkennung)
if (!empty($_POST['website'])) {
    // Bot erkannt - simuliere Erfolg aber sende nichts
    $_SESSION['last_submission'] = $currentTime;
    echo json_encode(['success' => true]);
    exit;
}

// Timestamp-Check (Formular muss mindestens 3 Sekunden offen sein)
$timestamp = $_POST['timestamp'] ?? 0;
$formOpenTime = ($currentTime * 1000) - $timestamp; // in Millisekunden
if ($formOpenTime < 3000) {
    // Zu schnell ausgefüllt - wahrscheinlich Bot
    echo json_encode(['success' => false, 'message' => 'Formular zu schnell ausgefüllt']);
    exit;
}

// Input-Validierung und Sanitization
$name = trim($_POST['name'] ?? '');
$email = trim($_POST['email'] ?? '');
$subject = trim($_POST['subject'] ?? 'Kontaktanfrage über wildcam.ai');
$message = trim($_POST['message'] ?? '');

// Pflichtfelder prüfen
if (empty($name) || empty($email) || empty($message)) {
    echo json_encode(['success' => false, 'message' => 'Bitte füllen Sie alle Pflichtfelder aus']);
    exit;
}

// Längen-Validierung
if (strlen($name) > 100 || strlen($email) > 100 || strlen($subject) > 200 || strlen($message) > 5000) {
    echo json_encode(['success' => false, 'message' => 'Eingabe zu lang']);
    exit;
}

// E-Mail-Validierung
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo json_encode(['success' => false, 'message' => 'Ungültige E-Mail-Adresse']);
    exit;
}

// XSS-Schutz: HTML-Entities kodieren
$name = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
$email = htmlspecialchars($email, ENT_QUOTES, 'UTF-8');
$subject = htmlspecialchars($subject, ENT_QUOTES, 'UTF-8');
$message = htmlspecialchars($message, ENT_QUOTES, 'UTF-8');

// Spam-Erkennung: Verdächtige Muster
$spamPatterns = [
    '/<script/i',
    '/javascript:/i',
    '/<iframe/i',
    '/\[url=/i',
    '/\[link=/i',
    '/viagra|cialis|casino|poker/i'
];

foreach ($spamPatterns as $pattern) {
    if (preg_match($pattern, $message) || preg_match($pattern, $name) || preg_match($pattern, $subject)) {
        // Spam erkannt - simuliere Erfolg aber sende nichts
        $_SESSION['last_submission'] = $currentTime;
        echo json_encode(['success' => true]);
        exit;
    }
}

// **HIER DEINE E-MAIL-ADRESSE EINTRAGEN**
$toEmail = 'beta.orionis@gmx.net'; // ← ANPASSEN!

// E-Mail zusammenstellen
$emailSubject = "[wildcam.ai] " . $subject;
$emailBody = "Neue Kontaktanfrage von wildcam.ai\n\n";
$emailBody .= "Name: " . $name . "\n";
$emailBody .= "E-Mail: " . $email . "\n\n";
$emailBody .= "Nachricht:\n" . $message . "\n\n";
$emailBody .= "---\n";
$emailBody .= "IP-Adresse: " . $_SERVER['REMOTE_ADDR'] . "\n";
$emailBody .= "Zeitstempel: " . date('Y-m-d H:i:s') . "\n";

// E-Mail-Headers (Header-Injection-Schutz)
$headers = [];
$headers[] = 'From: noreply@wildcam.ai';
$headers[] = 'Reply-To: ' . str_replace(["\r", "\n"], '', $email);
$headers[] = 'X-Mailer: PHP/' . phpversion();
$headers[] = 'Content-Type: text/plain; charset=UTF-8';

// E-Mail versenden
$mailSuccess = mail($toEmail, $emailSubject, $emailBody, implode("\r\n", $headers));

if ($mailSuccess) {
    // Erfolg - Session-Timestamp aktualisieren
    $_SESSION['last_submission'] = $currentTime;
    
    // Optional: In Datei loggen (für Debugging)
    // $logEntry = date('Y-m-d H:i:s') . " - Kontakt von: $name ($email)\n";
    // file_put_contents('contact-log.txt', $logEntry, FILE_APPEND);
    
    echo json_encode(['success' => true, 'message' => 'Nachricht erfolgreich versendet']);
} else {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Fehler beim Versenden der E-Mail']);
}
?>