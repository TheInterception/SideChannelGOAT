<?php
/**
 * VULNERABLE PHP APPLICATION - FOR EDUCATIONAL PURPOSES ONLY
 * Side Channel Vulnerabilities Demonstration
 * 
 * WARNING: This application contains intentional security vulnerabilities.
 * DO NOT deploy this to production or any internet-facing server.
 * Use only in isolated testing environments.
 */

session_start();

// Initialize demo data
if (!isset($_SESSION['users'])) {
    $_SESSION['users'] = [
        'admin' => ['password' => 'Admin123!@#', 'role' => 'admin', 'failed_attempts' => 0],
        'user1' => ['password' => 'User123!@#', 'role' => 'user', 'failed_attempts' => 0],
        'user2' => ['password' => 'Pass123!@#', 'role' => 'user', 'failed_attempts' => 0]
    ];
}

if (!isset($_SESSION['secret_keys'])) {
    $_SESSION['secret_keys'] = [
        'KEY1' => 'SECRET_API_KEY_12345',
        'KEY2' => 'SECRET_API_KEY_67890'
    ];
}

$vulnerability = $_GET['vuln'] ?? 'home';
$action = $_POST['action'] ?? '';

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Side Channel Vulnerabilities Demo</title>
    <link href="https://fonts.googleapis.com/css2?family=Teko:wght@700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
        }
        header { 
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white; 
            padding: 40px 30px; 
            border-radius: 12px; 
            margin-bottom: 25px; 
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            border: 1px solid rgba(255,255,255,0.1);
            position: relative;
            overflow: hidden;
        }
        header:before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 120"><path d="M0,0 Q300,60 600,30 T1200,0 L1200,120 L0,120 Z" fill="rgba(255,255,255,0.03)"/></svg>') no-repeat bottom;
            background-size: cover;
            opacity: 0.6;
        }
        .logo-container {
            position: relative;
            z-index: 1;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 20px;
        }
        .logo-icon {
            width: 80px;
            height: 80px;
            filter: drop-shadow(0 0 15px rgba(255,255,255,0.3));
        }
        .logo {
            font-family: 'Teko', sans-serif;
            font-size: 4.5em;
            font-weight: 700;
            letter-spacing: 3px;
            background: linear-gradient(45deg, #ff0000, #ff6b6b, #ffffff, #4ecdc4);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            text-shadow: 0 0 30px rgba(255,255,255,0.3);
            text-transform: uppercase;
            display: inline-block;
            animation: glow 3s ease-in-out infinite;
            position: relative;
        }
        @keyframes glow {
            0%, 100% { filter: drop-shadow(0 0 10px rgba(255,255,255,0.5)); }
            50% { filter: drop-shadow(0 0 20px rgba(255,255,255,0.8)); }
        }
        .logo:after {
            content: 'SideChannelGOAT';
            position: absolute;
            left: 0;
            top: 0;
            z-index: -1;
            background: linear-gradient(45deg, rgba(255,0,0,0.3), rgba(78,205,196,0.3));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            filter: blur(10px);
        }
        h1 { 
            margin-bottom: 10px; 
            font-size: 2.2em;
            font-weight: 600;
            letter-spacing: -0.5px;
            position: relative;
            z-index: 1;
        }
        header p {
            opacity: 0.9;
            font-size: 1.05em;
        }
        .warning { 
            background: linear-gradient(135deg, #c94b4b 0%, #e74c3c 100%);
            color: white; 
            padding: 20px; 
            border-radius: 10px; 
            margin-bottom: 25px; 
            box-shadow: 0 5px 15px rgba(231,76,60,0.3);
            border-left: 5px solid #a93226;
            font-weight: 500;
        }
        nav { 
            background: white; 
            padding: 20px; 
            border-radius: 12px; 
            margin-bottom: 25px; 
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }
        nav a { 
            padding: 10px 18px; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; 
            text-decoration: none; 
            border-radius: 8px;
            font-weight: 500;
            transition: all 0.3s ease;
            box-shadow: 0 3px 10px rgba(102,126,234,0.3);
            font-size: 0.95em;
        }
        nav a:hover { 
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102,126,234,0.4);
        }
        .content { 
            background: white; 
            padding: 40px; 
            border-radius: 12px; 
            box-shadow: 0 10px 40px rgba(0,0,0,0.15);
            min-height: 400px;
        }
        .content h2 {
            color: #2c3e50;
            margin-bottom: 20px;
            font-size: 1.8em;
            font-weight: 600;
        }
        .content h3 {
            color: #34495e;
            margin: 25px 0 15px 0;
            font-size: 1.4em;
            font-weight: 600;
        }
        .content h4 {
            color: #555;
            margin: 20px 0 10px 0;
            font-size: 1.1em;
            font-weight: 600;
        }
        .content p {
            line-height: 1.8;
            color: #555;
        }
        .vuln-card { 
            border: 2px solid #e74c3c; 
            padding: 25px; 
            margin-bottom: 25px; 
            border-radius: 12px; 
            background: linear-gradient(to bottom, #fff5f5 0%, #fef5f5 100%);
            box-shadow: 0 3px 15px rgba(231,76,60,0.1);
        }
        .vuln-title { 
            color: #e74c3c; 
            font-size: 1.5em; 
            font-weight: 700; 
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .vuln-title:before {
            content: "🔓";
            font-size: 1.2em;
        }
        .vuln-desc { 
            margin-bottom: 20px; 
            line-height: 1.8;
            color: #666;
            background: white;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #e74c3c;
        }
        form { 
            margin: 20px 0;
            background: white;
            padding: 20px;
            border-radius: 10px;
            border: 1px solid #e8e8e8;
        }
        input, textarea { 
            padding: 12px 15px; 
            margin: 8px 0; 
            border: 2px solid #e0e0e0; 
            border-radius: 8px; 
            width: 100%;
            max-width: 400px;
            display: block;
            font-size: 0.95em;
            transition: border 0.3s ease;
        }
        input:focus, textarea:focus {
            outline: none;
            border-color: #667eea;
        }
        button { 
            padding: 12px 25px; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; 
            border: none; 
            border-radius: 8px; 
            cursor: pointer; 
            margin: 15px 5px 10px 0;
            font-weight: 600;
            font-size: 0.95em;
            transition: all 0.3s ease;
            box-shadow: 0 4px 12px rgba(102,126,234,0.3);
        }
        button:hover { 
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(102,126,234,0.4);
        }
        .result { 
            background: #f8f9fa; 
            padding: 20px; 
            margin: 20px 0; 
            border-radius: 10px; 
            border-left: 5px solid #667eea;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }
        .result strong {
            color: #2c3e50;
        }
        .error { 
            background: linear-gradient(to right, #fff5f5 0%, #ffe8e8 100%);
            border-left-color: #e74c3c;
        }
        .success { 
            background: linear-gradient(to right, #f0fdf4 0%, #dcfce7 100%);
            border-left-color: #27ae60;
        }
        .code { 
            background: #1e293b;
            color: #e2e8f0; 
            padding: 20px; 
            border-radius: 10px; 
            overflow-x: auto; 
            font-family: 'Fira Code', 'Courier New', monospace; 
            margin: 20px 0;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
            border: 1px solid #334155;
            line-height: 1.6;
        }
        table { 
            width: 100%; 
            border-collapse: separate;
            border-spacing: 0;
            margin: 20px 0;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
        }
        th, td { 
            padding: 15px; 
            text-align: left; 
            border-bottom: 1px solid #e8e8e8;
        }
        th { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 0.5px;
        }
        tr:last-child td {
            border-bottom: none;
        }
        tr:hover td {
            background: #f8f9fa;
        }
        .mitigation { 
            background: linear-gradient(to bottom, #f0fdf4 0%, #dcfce7 100%);
            border: 2px solid #27ae60; 
            padding: 25px; 
            margin-top: 30px; 
            border-radius: 12px;
            box-shadow: 0 3px 15px rgba(39,174,96,0.1);
        }
        .mitigation h3 { 
            color: #27ae60; 
            margin-bottom: 15px;
            font-size: 1.4em;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .mitigation h3:before {
            content: "✅";
            font-size: 1.2em;
        }
        .mitigation ul {
            margin-left: 25px;
            line-height: 2;
        }
        .mitigation li {
            color: #555;
            margin: 8px 0;
        }
        em {
            color: #667eea;
            font-style: normal;
            font-weight: 500;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo-container">
                <svg class="logo-icon" viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg">
                    <!-- Shield outline with crack -->
                    <defs>
                        <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                            <stop offset="0%" style="stop-color:#ff4444;stop-opacity:1" />
                            <stop offset="50%" style="stop-color:#ff6b6b;stop-opacity:1" />
                            <stop offset="100%" style="stop-color:#ff8888;stop-opacity:1" />
                        </linearGradient>
                        <linearGradient id="lockGrad" x1="0%" y1="0%" x2="0%" y2="100%">
                            <stop offset="0%" style="stop-color:#ffffff;stop-opacity:1" />
                            <stop offset="100%" style="stop-color:#cccccc;stop-opacity:1" />
                        </linearGradient>
                        <filter id="glow">
                            <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
                            <feMerge>
                                <feMergeNode in="coloredBlur"/>
                                <feMergeNode in="SourceGraphic"/>
                            </feMerge>
                        </filter>
                    </defs>
                    
                    <!-- Background circle -->
                    <circle cx="100" cy="100" r="95" fill="rgba(255,255,255,0.1)" stroke="rgba(255,255,255,0.3)" stroke-width="2"/>
                    
                    <!-- Shield shape -->
                    <path d="M100,30 L150,50 L150,110 Q150,140 100,160 Q50,140 50,110 L50,50 Z" 
                          fill="url(#shieldGrad)" 
                          stroke="#cc0000" 
                          stroke-width="3"
                          filter="url(#glow)"/>
                    
                    <!-- Crack lines through shield -->
                    <path d="M100,45 L105,70 L95,90 L100,120 L90,145" 
                          stroke="#330000" 
                          stroke-width="2.5" 
                          fill="none" 
                          opacity="0.6"
                          stroke-linecap="round"/>
                    <path d="M100,45 L95,70 L105,90 L100,120 L110,145" 
                          stroke="#330000" 
                          stroke-width="2.5" 
                          fill="none" 
                          opacity="0.6"
                          stroke-linecap="round"/>
                    
                    <!-- Broken lock -->
                    <g transform="translate(100,85)">
                        <!-- Lock body -->
                        <rect x="-15" y="5" width="30" height="35" rx="4" 
                              fill="url(#lockGrad)" 
                              stroke="#999" 
                              stroke-width="2"/>
                        <!-- Keyhole -->
                        <circle cx="0" cy="17" r="4" fill="#333"/>
                        <rect x="-2" y="17" width="4" height="10" fill="#333"/>
                        
                        <!-- Broken shackle (left part) -->
                        <path d="M-15,5 L-15,-10 Q-15,-20 -5,-20" 
                              stroke="#999" 
                              stroke-width="4" 
                              fill="none" 
                              stroke-linecap="round"/>
                        <!-- Broken shackle (right part) -->
                        <path d="M15,5 L15,-5" 
                              stroke="#999" 
                              stroke-width="4" 
                              fill="none" 
                              stroke-linecap="round"/>
                        <!-- Break effect -->
                        <circle cx="8" cy="-8" r="2" fill="#ffcc00"/>
                        <circle cx="10" cy="-10" r="1.5" fill="#ffcc00" opacity="0.7"/>
                        <circle cx="12" cy="-6" r="1" fill="#ffcc00" opacity="0.5"/>
                    </g>
                    
                    <!-- Binary code flowing -->
                    <text x="30" y="180" font-family="monospace" font-size="10" fill="rgba(255,255,255,0.4)">01001000</text>
                    <text x="120" y="190" font-family="monospace" font-size="10" fill="rgba(255,255,255,0.4)">10110</text>
                    
                    <!-- Warning triangles at corners -->
                    <path d="M170,30 L175,40 L165,40 Z" fill="#ffcc00" opacity="0.8"/>
                    <text x="168" y="39" font-size="10" fill="#333">!</text>
                    <path d="M30,170 L35,180 L25,180 Z" fill="#ffcc00" opacity="0.8"/>
                    <text x="28" y="179" font-size="10" fill="#333">!</text>
                </svg>
                <div class="logo">SideChannelGOAT</div>
            </div>
            <h1>🔒 Side Channel Vulnerabilities Demo Lab</h1>
            <p>Educational PHP Application - DO NOT USE IN PRODUCTION</p>
        </header>

        <div class="warning">
            ⚠️ <strong>WARNING:</strong> This application contains intentional security vulnerabilities for educational purposes only. Use only in isolated testing environments.
        </div>

        <nav>
            <a href="?vuln=home">Home</a>
            <a href="?vuln=timing1">Timing Attack #1</a>
            <a href="?vuln=timing2">Timing Attack #2</a>
            <a href="?vuln=timing3">Timing Attack #3</a>
            <a href="?vuln=error">Error-Based</a>
            <a href="?vuln=cache">Cache Timing</a>
            <a href="?vuln=resource">Resource Usage</a>
            <a href="?vuln=response">Response Size</a>
            <a href="?vuln=sequential">Sequential Timing</a>
            <a href="?vuln=boolean">Boolean Timing</a>
            <a href="?vuln=stats">Statistical</a>
        </nav>

        <div class="content">
            <?php

            // HOME PAGE
            if ($vulnerability === 'home') {
                ?>
                <h2>Welcome to the Side Channel Vulnerabilities Lab</h2>
                <p style="margin: 20px 0; line-height: 1.8;">
                    This application demonstrates 10 different side-channel vulnerabilities commonly found in web applications.
                    Each vulnerability includes working examples and mitigation strategies.
                </p>
                
                <h3 style="margin-top: 30px;">Available Vulnerabilities:</h3>
                <table>
                    <tr>
                        <th>#</th>
                        <th>Vulnerability Type</th>
                        <th>Description</th>
                    </tr>
                    <tr>
                        <td>1</td>
                        <td>String Comparison Timing</td>
                        <td>Character-by-character comparison leaks password length</td>
                    </tr>
                    <tr>
                        <td>2</td>
                        <td>Username Enumeration Timing</td>
                        <td>Different processing times for valid/invalid usernames</td>
                    </tr>
                    <tr>
                        <td>3</td>
                        <td>Database Query Timing</td>
                        <td>Query execution time reveals data existence</td>
                    </tr>
                    <tr>
                        <td>4</td>
                        <td>Error Message Disclosure</td>
                        <td>Different errors reveal system information</td>
                    </tr>
                    <tr>
                        <td>5</td>
                        <td>Cache Timing Attack</td>
                        <td>Cache hits/misses reveal accessed data</td>
                    </tr>
                    <tr>
                        <td>6</td>
                        <td>Resource Exhaustion Timing</td>
                        <td>Password complexity affects response time</td>
                    </tr>
                    <tr>
                        <td>7</td>
                        <td>Response Size Leak</td>
                        <td>Response length reveals information</td>
                    </tr>
                    <tr>
                        <td>8</td>
                        <td>Sequential Processing Timing</td>
                        <td>Array iteration time leaks data position</td>
                    </tr>
                    <tr>
                        <td>9</td>
                        <td>Boolean Blind Timing</td>
                        <td>True/false conditions have different timings</td>
                    </tr>
                    <tr>
                        <td>10</td>
                        <td>Statistical Timing Analysis</td>
                        <td>Multiple requests reveal timing patterns</td>
                    </tr>
                </table>
                <?php
            }

            // VULNERABILITY 1: String Comparison Timing Attack
            elseif ($vulnerability === 'timing1') {
                ?>
                <div class="vuln-card">
                    <div class="vuln-title">Vulnerability #1: String Comparison Timing Attack</div>
                    <div class="vuln-desc">
                        This vulnerability uses character-by-character comparison which stops at the first mismatch.
                        An attacker can measure response time to determine correct password characters one by one.
                    </div>
                    
                    <h4>Try It:</h4>
                    <form method="POST">
                        <input type="hidden" name="action" value="timing1">
                        <input type="text" name="password" placeholder="Enter password" required>
                        <button type="submit">Check Password</button>
                    </form>

                    <?php
                    if ($action === 'timing1') {
                        $correct_password = "SecretPass123";
                        $input = $_POST['password'] ?? '';
                        
                        $start = microtime(true);
                        
                        // VULNERABLE: Character-by-character comparison
                        $is_valid = false;
                        if (strlen($input) === strlen($correct_password)) {
                            $is_valid = true;
                            for ($i = 0; $i < strlen($correct_password); $i++) {
                                if ($input[$i] !== $correct_password[$i]) {
                                    $is_valid = false;
                                    break; // Stops early - timing leak!
                                }
                                // Simulate some processing delay
                                usleep(1000); // 1ms per character
                            }
                        }
                        
                        $end = microtime(true);
                        $time_taken = ($end - $start) * 1000;
                        
                        echo '<div class="result ' . ($is_valid ? 'success' : 'error') . '">';
                        echo '<strong>Result:</strong> ' . ($is_valid ? 'Password Correct!' : 'Password Incorrect') . '<br>';
                        echo '<strong>Time Taken:</strong> ' . number_format($time_taken, 2) . ' ms<br>';
                        echo '<strong>Hint:</strong> Notice how longer correct prefixes take more time!';
                        echo '</div>';
                        
                        echo '<p style="margin-top: 15px;"><strong>Correct Password:</strong> ' . $correct_password . '</p>';
                        echo '<p><strong>Your Input:</strong> ' . htmlspecialchars($input) . '</p>';
                    }
                    ?>
                </div>

                <div class="mitigation">
                    <h3>✅ Mitigation Strategy</h3>
                    <p><strong>Use constant-time comparison:</strong></p>
                    <div class="code">// SECURE: Constant-time comparison
$is_valid = hash_equals($correct_password, $input);

// Or use PHP's built-in
$is_valid = password_verify($input, password_hash($correct_password, PASSWORD_DEFAULT));</div>
                    <p style="margin-top: 10px;"><strong>Key Points:</strong></p>
                    <ul style="margin-left: 20px; margin-top: 10px;">
                        <li>Always use hash_equals() for string comparison</li>
                        <li>Never use == or === for sensitive data comparison</li>
                        <li>Avoid early-exit conditions in security checks</li>
                    </ul>
                </div>
                <?php
            }

            // VULNERABILITY 2: Username Enumeration via Timing
            elseif ($vulnerability === 'timing2') {
                ?>
                <div class="vuln-card">
                    <div class="vuln-title">Vulnerability #2: Username Enumeration Timing Attack</div>
                    <div class="vuln-desc">
                        Different code paths for valid vs invalid usernames create timing differences.
                        Valid usernames trigger password verification (slow), invalid ones exit early (fast).
                    </div>
                    
                    <h4>Try It:</h4>
                    <form method="POST">
                        <input type="hidden" name="action" value="timing2">
                        <input type="text" name="username" placeholder="Username" required>
                        <input type="password" name="password" placeholder="Password" required>
                        <button type="submit">Login</button>
                    </form>

                    <p style="margin-top: 10px;"><em>Try: admin, user1, user2, or invalid names</em></p>

                    <?php
                    if ($action === 'timing2') {
                        $username = $_POST['username'] ?? '';
                        $password = $_POST['password'] ?? '';
                        
                        $start = microtime(true);
                        
                        // VULNERABLE: Different timing for valid/invalid usernames
                        if (isset($_SESSION['users'][$username])) {
                            // Slow path: password verification
                            usleep(50000); // 50ms - simulates bcrypt/argon2
                            $stored = $_SESSION['users'][$username]['password'];
                            $is_valid = ($password === $stored);
                        } else {
                            // Fast path: immediate rejection
                            $is_valid = false;
                        }
                        
                        $end = microtime(true);
                        $time_taken = ($end - $start) * 1000;
                        
                        echo '<div class="result ' . ($is_valid ? 'success' : 'error') . '">';
                        echo '<strong>Result:</strong> ' . ($is_valid ? 'Login Successful!' : 'Invalid Credentials') . '<br>';
                        echo '<strong>Time Taken:</strong> ' . number_format($time_taken, 2) . ' ms<br>';
                        echo '<strong>Analysis:</strong> ' . (isset($_SESSION['users'][$username]) ? 'Valid username (slow)' : 'Invalid username (fast)');
                        echo '</div>';
                    }
                    ?>
                </div>

                <div class="mitigation">
                    <h3>✅ Mitigation Strategy</h3>
                    <p><strong>Always perform password verification regardless of username validity:</strong></p>
                    <div class="code">// SECURE: Constant timing regardless of username
$dummy_hash = password_hash('dummy', PASSWORD_DEFAULT);
$stored_hash = $_SESSION['users'][$username]['password'] ?? $dummy_hash;

// Always verify, even with dummy hash
$is_valid = password_verify($password, $stored_hash) && isset($_SESSION['users'][$username]);</div>
                    <p style="margin-top: 10px;"><strong>Additional Measures:</strong></p>
                    <ul style="margin-left: 20px; margin-top: 10px;">
                        <li>Use rate limiting to prevent timing analysis</li>
                        <li>Add random delays (sleep(rand(100, 500)))</li>
                        <li>Return generic error messages</li>
                    </ul>
                </div>
                <?php
            }

            // VULNERABILITY 3: Database Query Timing
            elseif ($vulnerability === 'timing3') {
                ?>
                <div class="vuln-card">
                    <div class="vuln-title">Vulnerability #3: Database Query Timing Attack</div>
                    <div class="vuln-desc">
                        Complex database queries take longer when they find matches. Attackers can infer
                        data existence by measuring query response times.
                    </div>
                    
                    <h4>Try It:</h4>
                    <form method="POST">
                        <input type="hidden" name="action" value="timing3">
                        <input type="text" name="search_key" placeholder="Search for API key" required>
                        <button type="submit">Search</button>
                    </form>

                    <p style="margin-top: 10px;"><em>Try: KEY1, KEY2, INVALID_KEY</em></p>

                    <?php
                    if ($action === 'timing3') {
                        $search_key = $_POST['search_key'] ?? '';
                        
                        $start = microtime(true);
                        
                        // VULNERABLE: Query time depends on result set
                        $found = false;
                        if (isset($_SESSION['secret_keys'][$search_key])) {
                            // Simulate complex query processing
                            usleep(30000); // 30ms for found keys
                            $found = true;
                        }
                        // No delay for not found - timing leak!
                        
                        $end = microtime(true);
                        $time_taken = ($end - $start) * 1000;
                        
                        echo '<div class="result ' . ($found ? 'success' : 'error') . '">';
                        echo '<strong>Result:</strong> ' . ($found ? 'Key Exists' : 'Key Not Found') . '<br>';
                        echo '<strong>Time Taken:</strong> ' . number_format($time_taken, 2) . ' ms<br>';
                        echo '<strong>Leak:</strong> Response time reveals key existence!';
                        echo '</div>';
                    }
                    ?>
                </div>

                <div class="mitigation">
                    <h3>✅ Mitigation Strategy</h3>
                    <p><strong>Ensure consistent query execution time:</strong></p>
                    <div class="code">// SECURE: Always perform same work
$start_time = microtime(true);
$found = isset($_SESSION['secret_keys'][$search_key]);

// Always wait minimum time
$target_time = 0.030; // 30ms
$elapsed = microtime(true) - $start_time;
if ($elapsed < $target_time) {
    usleep(($target_time - $elapsed) * 1000000);
}</div>
                    <p style="margin-top: 10px;"><strong>Database-Level Fixes:</strong></p>
                    <ul style="margin-left: 20px; margin-top: 10px;">
                        <li>Use indexed columns for constant-time lookups</li>
                        <li>Implement query result caching</li>
                        <li>Add artificial delays for all queries</li>
                    </ul>
                </div>
                <?php
            }

            // VULNERABILITY 4: Error Message Side Channel
            elseif ($vulnerability === 'error') {
                ?>
                <div class="vuln-card">
                    <div class="vuln-title">Vulnerability #4: Error Message Information Disclosure</div>
                    <div class="vuln-desc">
                        Different error messages reveal system internals. Attackers use these to map
                        application structure and valid usernames.
                    </div>
                    
                    <h4>Try It:</h4>
                    <form method="POST">
                        <input type="hidden" name="action" value="error">
                        <input type="text" name="username" placeholder="Username" required>
                        <input type="password" name="password" placeholder="Password" required>
                        <button type="submit">Login</button>
                    </form>

                    <?php
                    if ($action === 'error') {
                        $username = $_POST['username'] ?? '';
                        $password = $_POST['password'] ?? '';
                        
                        // VULNERABLE: Detailed error messages
                        if (!isset($_SESSION['users'][$username])) {
                            echo '<div class="result error">';
                            echo '<strong>Error:</strong> Username "' . htmlspecialchars($username) . '" does not exist in the system.';
                            echo '</div>';
                        } elseif ($_SESSION['users'][$username]['password'] !== $password) {
                            echo '<div class="result error">';
                            echo '<strong>Error:</strong> Password incorrect for user "' . htmlspecialchars($username) . '".';
                            echo '</div>';
                        } elseif ($_SESSION['users'][$username]['failed_attempts'] >= 3) {
                            echo '<div class="result error">';
                            echo '<strong>Error:</strong> Account "' . htmlspecialchars($username) . '" is locked due to multiple failed attempts.';
                            echo '</div>';
                        } else {
                            echo '<div class="result success">';
                            echo '<strong>Success:</strong> Login successful!';
                            echo '</div>';
                        }
                    }
                    ?>
                </div>

                <div class="mitigation">
                    <h3>✅ Mitigation Strategy</h3>
                    <p><strong>Use generic error messages:</strong></p>
                    <div class="code">// SECURE: Generic error message
if (!$is_valid) {
    echo "Invalid username or password.";
    // Log actual error server-side
    error_log("Login failed: username=$username, reason=$reason");
}</div>
                    <p style="margin-top: 10px;"><strong>Best Practices:</strong></p>
                    <ul style="margin-left: 20px; margin-top: 10px;">
                        <li>Never reveal which field is incorrect</li>
                        <li>Use same message for all authentication failures</li>
                        <li>Log detailed errors server-side only</li>
                        <li>Implement proper error handling without information leakage</li>
                    </ul>
                </div>
                <?php
            }

            // VULNERABILITY 5: Cache Timing Attack
            elseif ($vulnerability === 'cache') {
                ?>
                <div class="vuln-card">
                    <div class="vuln-title">Vulnerability #5: Cache Timing Attack</div>
                    <div class="vuln-desc">
                        Cached data returns faster than uncached data. Attackers can determine
                        which data has been accessed recently by measuring response times.
                    </div>
                    
                    <h4>Try It:</h4>
                    <form method="POST">
                        <input type="hidden" name="action" value="cache">
                        <input type="text" name="user_id" placeholder="User ID (admin, user1, user2)" required>
                        <button type="submit">Get User Data</button>
                    </form>

                    <?php
                    if ($action === 'cache') {
                        $user_id = $_POST['user_id'] ?? '';
                        
                        if (!isset($_SESSION['cache'])) {
                            $_SESSION['cache'] = [];
                        }
                        
                        $start = microtime(true);
                        
                        // VULNERABLE: Different timing for cached vs uncached
                        if (isset($_SESSION['cache'][$user_id])) {
                            // Cache hit - fast
                            $data = $_SESSION['cache'][$user_id];
                            $cache_status = 'HIT';
                        } else {
                            // Cache miss - slow
                            usleep(40000); // 40ms - simulate database query
                            if (isset($_SESSION['users'][$user_id])) {
                                $data = $_SESSION['users'][$user_id];
                                $_SESSION['cache'][$user_id] = $data;
                                $cache_status = 'MISS';
                            } else {
                                $data = null;
                                $cache_status = 'MISS';
                            }
                        }
                        
                        $end = microtime(true);
                        $time_taken = ($end - $start) * 1000;
                        
                        echo '<div class="result">';
                        echo '<strong>Cache Status:</strong> ' . $cache_status . '<br>';
                        echo '<strong>Time Taken:</strong> ' . number_format($time_taken, 2) . ' ms<br>';
                        echo '<strong>Leak:</strong> ' . ($cache_status === 'HIT' ? 'This user was recently accessed!' : 'Not in cache (first access or invalid)');
                        echo '</div>';
                    }
                    ?>
                </div>

                <div class="mitigation">
                    <h3>✅ Mitigation Strategy</h3>
                    <p><strong>Add consistent delays to normalize timing:</strong></p>
                    <div class="code">// SECURE: Constant time regardless of cache status
$min_time = 0.040; // Always take at least 40ms
$start = microtime(true);

$data = $_SESSION['cache'][$user_id] ?? null;
if ($data === null) {
    $data = fetch_from_database($user_id);
    $_SESSION['cache'][$user_id] = $data;
}

// Pad to minimum time
$elapsed = microtime(true) - $start;
if ($elapsed < $min_time) {
    usleep(($min_time - $elapsed) * 1000000);
}</div>
                    <p style="margin-top: 10px;"><strong>Alternative Approaches:</strong></p>
                    <ul style="margin-left: 20px; margin-top: 10px;">
                        <li>Disable timing-based cache analysis via CDN</li>
                        <li>Pre-warm cache with dummy data</li>
                        <li>Use random delays within acceptable range</li>
                    </ul>
                </div>
                <?php
            }

            // VULNERABILITY 6: Resource Exhaustion Timing
            elseif ($vulnerability === 'resource') {
                ?>
                <div class="vuln-card">
                    <div class="vuln-title">Vulnerability #6: Resource Exhaustion Timing Attack</div>
                    <div class="vuln-desc">
                        Password hashing with adaptive algorithms (bcrypt, argon2) takes longer for
                        valid users. Attackers can enumerate valid usernames by observing CPU usage timing.
                    </div>
                    
                    <h4>Try It:</h4>
                    <form method="POST">
                        <input type="hidden" name="action" value="resource">
                        <input type="text" name="username" placeholder="Username" required>
                        <input type="password" name="password" placeholder="Password" required>
                        <button type="submit">Login</button>
                    </form>

                    <?php
                    if ($action === 'resource') {
                        $username = $_POST['username'] ?? '';
                        $password = $_POST['password'] ?? '';
                        
                        $start = microtime(true);
                        
                        // VULNERABLE: Expensive operation only for valid users
                        if (isset($_SESSION['users'][$username])) {
                            // Simulate bcrypt (expensive)
                            for ($i = 0; $i < 100; $i++) {
                                hash('sha256', $password . $i);
                            }
                            usleep(80000); // 80ms
                            $is_valid = ($_SESSION['users'][$username]['password'] === $password);
                        } else {
                            // No expensive operation for invalid users
                            $is_valid = false;
                        }
                        
                        $end = microtime(true);
                        $time_taken = ($end - $start) * 1000;
                        
                        echo '<div class="result ' . ($is_valid ? 'success' : 'error') . '">';
                        echo '<strong>Result:</strong> ' . ($is_valid ? 'Login Successful' : 'Invalid Credentials') . '<br>';
                        echo '<strong>Time Taken:</strong> ' . number_format($time_taken, 2) . ' ms<br>';
                        echo '<strong>Leak:</strong> ' . (isset($_SESSION['users'][$username]) ? 'Valid username (expensive hash)' : 'Invalid username (no hashing)');
                        echo '</div>';
                    }
                    ?>
                </div>

                <div class="mitigation">
                    <h3>✅ Mitigation Strategy</h3>
                    <p><strong>Always perform expensive operations:</strong></p>
                    <div class="code">// SECURE: Hash password regardless of username validity
$dummy_hash = '$2y$10$dummy.hash.for.invalid.users.to.waste.time';
$user_hash = $_SESSION['users'][$username]['hash'] ?? $dummy_hash;

// Always verify (same cost)
$is_valid = password_verify($password, $user_hash);

// Additional check
$is_valid = $is_valid && isset($_SESSION['users'][$username]);</div>
                    <p style="margin-top: 10px;"><strong>Key Principles:</strong></p>
                    <ul style="margin-left: 20px; margin-top: 10px;">
                        <li>Always hash passwords, even for invalid usernames</li>
                        <li>Use pre-generated dummy hashes</li>
                        <li>Ensure consistent computational cost</li>
                    </ul>
                </div>
                <?php
            }

            // VULNERABILITY 7: Response Size Side Channel
            elseif ($vulnerability === 'response') {
                ?>
                <div class="vuln-card">
                    <div class="vuln-title">Vulnerability #7: Response Size Information Leak</div>
                    <div class="vuln-desc">
                        Different response sizes reveal information about query results. Attackers
                        analyze response lengths to infer data without seeing actual content.
                    </div>
                    
                    <h4>Try It:</h4>
                    <form method="POST">
                        <input type="hidden" name="action" value="response">
                        <input type="text" name="search" placeholder="Search term" required>
                        <button type="submit">Search</button>
                    </form>

                    <?php
                    if ($action === 'response') {
                        $search = $_POST['search'] ?? '';
                        
                        // VULNERABLE: Response size varies with results
                        ob_start();
                        
                        $results = [];
                        foreach ($_SESSION['users'] as $username => $data) {
                            if (stripos($username, $search) !== false) {
                                $results[] = $username;
                            }
                        }
                        
                        if (count($results) > 0) {
                            echo '<ul style="list-style: none; padding-left: 0;">';
                            foreach ($results as $result) {
                                echo '<li style="padding: 10px; margin: 5px 0; background: white; border-radius: 5px; border-left: 3px solid #667eea;">🔹 ' . htmlspecialchars($result) . ' - Role: ' . $_SESSION['users'][$result]['role'] . '</li>';
                            }
                            echo '</ul>';
                        } else {
                            echo '<p>No results found.</p>';
                        }
                        echo '</div>';
                        
                        $response_content = ob_get_clean();
                        $response_size = strlen($response_content);
                        
                        echo $response_content;
                        echo '<div class="result">';
                        echo '<strong>Response Size:</strong> ' . $response_size . ' bytes<br>';
                        echo '<strong>Leak:</strong> Response size reveals number of matches!';
                        echo '</div>';
                    }
                    ?>
                </div>

                <div class="mitigation">
                    <h3>✅ Mitigation Strategy</h3>
                    <p><strong>Pad responses to constant size:</strong></p>
                    <div class="code">// SECURE: Fixed response size with padding
$response = json_encode(['results' => $results]);
$target_size = 1024; // Fixed size

// Pad with random data
if (strlen($response) < $target_size) {
    $padding = str_repeat(' ', $target_size - strlen($response));
    $response .= $padding;
}

echo $response;</div>
                    <p style="margin-top: 10px;"><strong>Alternative Approaches:</strong></p>
                    <ul style="margin-left: 20px; margin-top: 10px;">
                        <li>Use compression to hide actual size</li>
                        <li>Return paginated results (constant page size)</li>
                        <li>Add random padding to all responses</li>
                    </ul>
                </div>
                <?php
            }

            // VULNERABILITY 8: Sequential Processing Timing
            elseif ($vulnerability === 'sequential') {
                ?>
                <div class="vuln-card">
                    <div class="vuln-title">Vulnerability #8: Sequential Processing Timing Attack</div>
                    <div class="vuln-desc">
                        Linear search through arrays reveals position of target data. Processing time
                        correlates with array position, allowing attackers to infer data location.
                    </div>
                    
                    <h4>Try It:</h4>
                    <form method="POST">
                        <input type="hidden" name="action" value="sequential">
                        <input type="text" name="token" placeholder="Enter access token" required>
                        <button type="submit">Validate Token</button>
                    </form>

                    <p style="margin-top: 10px;"><em>Try: TOKEN_001, TOKEN_500, TOKEN_999</em></p>

                    <?php
                    if ($action === 'sequential') {
                        $token = $_POST['token'] ?? '';
                        
                        // Create token array
                        if (!isset($_SESSION['tokens'])) {
                            $_SESSION['tokens'] = [];
                            for ($i = 1; $i <= 1000; $i++) {
                                $_SESSION['tokens'][] = 'TOKEN_' . str_pad($i, 3, '0', STR_PAD_LEFT);
                            }
                        }
                        
                        $start = microtime(true);
                        
                        // VULNERABLE: Linear search with early exit
                        $found = false;
                        $position = -1;
                        foreach ($_SESSION['tokens'] as $index => $valid_token) {
                            usleep(100); // 0.1ms per check
                            if ($token === $valid_token) {
                                $found = true;
                                $position = $index + 1;
                                break; // Early exit reveals position!
                            }
                        }
                        
                        $end = microtime(true);
                        $time_taken = ($end - $start) * 1000;
                        
                        echo '<div class="result ' . ($found ? 'success' : 'error') . '">';
                        echo '<strong>Result:</strong> ' . ($found ? 'Token Valid' : 'Token Invalid') . '<br>';
                        echo '<strong>Time Taken:</strong> ' . number_format($time_taken, 2) . ' ms<br>';
                        if ($found) {
                            echo '<strong>Position:</strong> ' . $position . ' of ' . count($_SESSION['tokens']) . '<br>';
                        }
                        echo '<strong>Leak:</strong> Time reveals token position in list!';
                        echo '</div>';
                    }
                    ?>
                </div>

                <div class="mitigation">
                    <h3>✅ Mitigation Strategy</h3>
                    <p><strong>Use hash-based lookups instead of linear search:</strong></p>
                    <div class="code">// SECURE: O(1) hash table lookup
$valid_tokens = array_flip($_SESSION['tokens']); // Create hash map

$start = microtime(true);
$found = isset($valid_tokens[$token]);
$end = microtime(true);

// Constant time regardless of position</div>
                    <p style="margin-top: 10px;"><strong>Additional Fixes:</strong></p>
                    <ul style="margin-left: 20px; margin-top: 10px;">
                        <li>Always process entire array (no early exit)</li>
                        <li>Use indexed database columns</li>
                        <li>Implement bloom filters for quick rejection</li>
                    </ul>
                </div>
                <?php
            }

            // VULNERABILITY 9: Boolean Blind Timing
            elseif ($vulnerability === 'boolean') {
                ?>
                <div class="vuln-card">
                    <div class="vuln-title">Vulnerability #9: Boolean Blind Timing Attack</div>
                    <div class="vuln-desc">
                        True and false conditions execute different code paths with measurably different
                        execution times. Attackers extract data bit-by-bit through timing analysis.
                    </div>
                    
                    <h4>Try It:</h4>
                    <form method="POST">
                        <input type="hidden" name="action" value="boolean">
                        <input type="text" name="user_check" placeholder="Check if username exists" required>
                        <button type="submit">Check</button>
                    </form>

                    <?php
                    if ($action === 'boolean') {
                        $user_check = $_POST['user_check'] ?? '';
                        
                        $start = microtime(true);
                        
                        // VULNERABLE: Different timing for true/false
                        if (isset($_SESSION['users'][$user_check])) {
                            // True condition - complex processing
                            $data = $_SESSION['users'][$user_check];
                            usleep(50000); // 50ms
                            for ($i = 0; $i < 100; $i++) {
                                hash('sha256', $data['password'] . $i);
                            }
                            $result = 'User exists';
                        } else {
                            // False condition - simple processing
                            $result = 'User not found';
                            // No delay!
                        }
                        
                        $end = microtime(true);
                        $time_taken = ($end - $start) * 1000;
                        
                        echo '<div class="result">';
                        echo '<strong>Result:</strong> ' . $result . '<br>';
                        echo '<strong>Time Taken:</strong> ' . number_format($time_taken, 2) . ' ms<br>';
                        echo '<strong>Leak:</strong> Timing reveals true/false without seeing result!';
                        echo '</div>';
                    }
                    ?>
                </div>

                <div class="mitigation">
                    <h3>✅ Mitigation Strategy</h3>
                    <p><strong>Execute same operations for both branches:</strong></p>
                    <div class="code">// SECURE: Same work regardless of condition
$start = microtime(true);

$exists = isset($_SESSION['users'][$user_check]);
$data = $exists ? $_SESSION['users'][$user_check] : ['password' => 'dummy'];

// Always do the same processing
usleep(50000);
for ($i = 0; $i < 100; $i++) {
    hash('sha256', $data['password'] . $i);
}

// Return result after constant time work
$result = $exists ? 'exists' : 'not found';</div>
                    <p style="margin-top: 10px;"><strong>Design Principles:</strong></p>
                    <ul style="margin-left: 20px; margin-top: 10px;">
                        <li>Balance both if/else branches</li>
                        <li>Use dummy operations when needed</li>
                        <li>Measure and test timing in production</li>
                    </ul>
                </div>
                <?php
            }

            // VULNERABILITY 10: Statistical Timing Analysis
            elseif ($vulnerability === 'stats') {
                ?>
                <div class="vuln-card">
                    <div class="vuln-title">Vulnerability #10: Statistical Timing Analysis Attack</div>
                    <div class="vuln-desc">
                        Even with added noise, statistical analysis of multiple requests can reveal
                        underlying timing patterns. Attackers use mean/median calculations to filter noise.
                    </div>
                    
                    <h4>Try It:</h4>
                    <form method="POST">
                        <input type="hidden" name="action" value="stats">
                        <input type="text" name="username" placeholder="Username to analyze" required>
                        <input type="number" name="iterations" value="50" min="10" max="100" placeholder="Iterations">
                        <button type="submit">Run Statistical Analysis</button>
                    </form>

                    <?php
                    if ($action === 'stats') {
                        $username = $_POST['username'] ?? '';
                        $iterations = min(100, max(10, intval($_POST['iterations'] ?? 50)));
                        
                        $times = [];
                        
                        for ($i = 0; $i < $iterations; $i++) {
                            $start = microtime(true);
                            
                            // VULNERABLE: Base timing difference with noise
                            if (isset($_SESSION['users'][$username])) {
                                usleep(30000 + rand(-5000, 5000)); // 30ms ± 5ms
                            } else {
                                usleep(10000 + rand(-5000, 5000)); // 10ms ± 5ms
                            }
                            
                            $end = microtime(true);
                            $times[] = ($end - $start) * 1000;
                        }
                        
                        $avg = array_sum($times) / count($times);
                        sort($times);
                        $median = $times[intval(count($times) / 2)];
                        $min = min($times);
                        $max = max($times);
                        
                        echo '<div class="result">';
                        echo '<strong>Statistical Analysis Results:</strong><br>';
                        echo '<strong>Iterations:</strong> ' . $iterations . '<br>';
                        echo '<strong>Average Time:</strong> ' . number_format($avg, 2) . ' ms<br>';
                        echo '<strong>Median Time:</strong> ' . number_format($median, 2) . ' ms<br>';
                        echo '<strong>Min Time:</strong> ' . number_format($min, 2) . ' ms<br>';
                        echo '<strong>Max Time:</strong> ' . number_format($max, 2) . ' ms<br>';
                        echo '<strong>Inference:</strong> ' . ($avg > 20 ? 'Likely VALID user (slower average)' : 'Likely INVALID user (faster average)');
                        echo '</div>';
                        
                        // Show distribution
                        echo '<h4>Timing Distribution:</h4>';
                        echo '<div style="background: #2c3e50; padding: 10px; border-radius: 5px; color: white; font-family: monospace; font-size: 12px;">';
                        foreach ($times as $idx => $time) {
                            $bar_length = intval(($time / $max) * 50);
                            echo sprintf("%3d: %6.2fms ", $idx + 1, $time);
                            echo str_repeat('█', $bar_length) . "\n";
                        }
                        echo '</div>';
                    }
                    ?>
                </div>

                <div class="mitigation">
                    <h3>✅ Mitigation Strategy</h3>
                    <p><strong>Use cryptographically secure random delays with large variance:</strong></p>
                    <div class="code">// SECURE: Large random delays mask base timing
$base_time = 50000; // 50ms base
$random_variance = random_int(0, 100000); // 0-100ms random

usleep($base_time + $random_variance);

// Result: Statistical analysis cannot determine pattern
// because variance is larger than timing difference</div>
                    <p style="margin-top: 10px;"><strong>Advanced Defenses:</strong></p>
                    <ul style="margin-left: 20px; margin-top: 10px;">
                        <li>Implement rate limiting (prevent multiple samples)</li>
                        <li>Use request queuing with batch processing</li>
                        <li>Add exponential backoff after multiple requests</li>
                        <li>Use CAPTCHA after threshold requests</li>
                    </ul>
                </div>
                <?php
            }

            ?>
        </div>
    </div>
</body>
</html>