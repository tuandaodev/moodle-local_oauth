<?php

// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * OAuth-protected logout endpoint.
 *
 * @package    local
 * @subpackage oauth
 * @copyright  2014 onwards Pau Ferrer Ocaña
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once '../../config.php';
require_once __DIR__ . '/lib.php';

\core\session\manager::write_close();

$server = oauth_get_server();
$request = OAuth2\Request::createFromGlobals();
$response = new OAuth2\Response();

if (!$server->verifyResourceRequest($request, $response)) {
    $response->send();
    die();
}

$token = $server->getAccessTokenData($request);
if (empty($token['user_id'])) {
    $response->setError(401, 'invalid_token', 'User not found.');
    $response->send();
    die();
}

$userid = (int)$token['user_id'];
if (!$DB->record_exists('user', ['id' => $userid])) {
    $response->setError(401, 'invalid_token', 'User not found.');
    $response->send();
    die();
}

\core\session\manager::kill_user_sessions($userid);

// Clear the browser session cookie to avoid "session timed out" message.
if (!empty($CFG->sessioncookie) && !empty($_COOKIE[$CFG->sessioncookie])) {
    $cookiepath = !empty($CFG->sessioncookiepath) ? $CFG->sessioncookiepath : '/';
    $cookiedomain = !empty($CFG->sessioncookiedomain) ? $CFG->sessioncookiedomain : '';
    $cookiesecure = !empty($CFG->cookiesecure);
    $cookiehttponly = !empty($CFG->cookiehttponly);
    setcookie($CFG->sessioncookie, '', time() - 3600, $cookiepath, $cookiedomain, $cookiesecure, $cookiehttponly);
    unset($_COOKIE[$CFG->sessioncookie]);
}

$response->setStatusCode(200);
$response->setParameter('status', 'logged_out');
$response->setParameter('user_id', $userid);
$response->send();
