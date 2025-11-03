<?php
declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

@session_start();
$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
$_SERVER['HTTP_USER_AGENT'] = 'phpunit/1.0';
