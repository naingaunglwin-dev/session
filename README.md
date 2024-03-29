<div align="center">

# Simple PHP Session Library
![Status](https://img.shields.io/badge/test-pass-green)
![Status](https://img.shields.io/badge/coverage-96.80%25-green)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

</div>

## Contributing
- This is an open-source library, and contributions are welcome.
- If you have any suggestions, bug reports, or feature requests, please open an issue or submit a pull request on the project repository.

## Requirement
- **PHP** version 8.0 or newer is required

## Installation & Setup
- You can just download the code from repo and use or download using composer.

### Download Using Composer
- If you don't have composer, install [composer](https://getcomposer.org/download/) first.
- create file `composer.json` at your project root directory.
- Add this to `composer.json`
```php
{
  "require": {
    "naingaunglwin-dev/session": "^1.0"
  }
}
```
- Run the following command in your terminal from the project's root directory:
```bash
composer install
```

If you already have `composer.json` file in your project, just run this command in your terminal,
```bash
composer require naingaunglwin-dev/session
```

## Usage
- In your php file,
```php
<?php

require_once "vendor/autoload.php";

use NAL\Session\Session;

// Create new instance of Session class
$session = new Session('test', (object)[
    'secure'   => true,
    'httpOnly' => true,
    'sameSite' => 'Strict',
    'timeOut'  => 3600
]);

// Session set
$session->set('username', 'david');

// Session get
$session->get('username'); //david

// Get all session data
$session->getAll();

// Session set flash message
$session->setFlashMessage('message', 'success');

// Session get flash message
$session->getFlashMessage('message');

// Delete Session
$session->destroy('key');

// Delete All Session
$session->destroy_all();

// Restart the session
$session->restart();
```
