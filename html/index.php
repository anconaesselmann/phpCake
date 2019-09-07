<?php

// ini_set('display_errors', 1);
// ini_set('display_startup_errors', 1);
// error_reporting(E_ALL);

// View models are resources (each resource has a urn?). API json file strings resources together. No need for View controllers
include_once("JWT.php");

function startsWith ($string, $startString) {
    $len = strlen($startString);
    return substr($string, 0, $len) === $startString;
}

class Environment {
    public $isLocal;

    function __construct() {
        $headers = getallheaders();
        $this->isLocal = array_key_exists("Host", $headers) ? (startsWith($headers["Host"], "192.168.1") || $headers["Host"] === "127.0.0.1") : false;
    }
}

class DevHeaders {
    public $json;
    public $userUuid;
    public $apiSecret;
    public $password;
    public $jwt;

    function __construct() {
        $query = new QuerryHeaders();
        $headers = new headers();
        $this->json = $query->json ? $query->json : $headers->json;
        $this->userUuid = $query->userUuid ?? $headers->userUuid;
        $this->apiSecret = $query->apiSecret ?? $headers->apiSecret;
        $this->password = $query->password ?? $headers->password;
        $this->jwt = $query->jwt ?? $headers->jwt;
    }
}

class QuerryHeaders {
    public $json;
    public $userUuid;
    public $apiSecret;
    public $password;
    public $jwt;

    function __construct() {
        $this->json = array_key_exists("json", $_GET) ? htmlspecialchars($_GET["json"]) === "true" : false;
        $this->userUuid = array_key_exists("user-uuid", $_GET) ? htmlspecialchars($_GET["user-uuid"]) : null;
        $this->apiSecret = array_key_exists("api-secret", $_GET) ? htmlspecialchars($_GET["api-secret"]) : null;
        $this->password = array_key_exists("password", $_GET) ? htmlspecialchars($_GET["password"]) : null;
        $this->jwt = array_key_exists("jwt", $_GET) ? htmlspecialchars($_GET["jwt"]) : null;
    }
}

class Headers {
    public $json;
    public $userUuid;
    public $apiSecret;
    public $password;
    public $jwt;

    function __construct() {
        $headers = getallheaders();
        $this->json = array_key_exists("Content-Type", $headers) ? $headers["Content-Type"] === "application/json" : false;
        $this->userUuid = array_key_exists("User", $headers) ? $headers["User"] : null;
        $this->apiSecret = array_key_exists("ApiSecret", $headers) ? $headers["ApiSecret"] : null;
        $this->password = array_key_exists("Password", $headers) ? $headers["Password"] : null;
        $this->jwt = array_key_exists("JWT", $headers) ? $headers["JWT"] : null;
    }
}

class Application {
    public $json;
    public $auth;
    public $headers;
    public $env;

    private static $_shared = null;

    public static function shared() {
        if (!self::$_shared) {
            self::$_shared = new Application();
        }
        return self::$_shared;
    }

    private function __construct() {
        $this->env = new Environment();
        $this->auth = new AuthManager();
        if ($this->env->isLocal) {
            $this->headers = new DevHeaders();
        } else {
            $this->headers = new Headers();
        }

        $apiSecret = "HBG72t2nVZAayeWRpbXqcP6fXqZTLw5G";

        $this->json = $this->headers->json;
        if (!$this->headers->userUuid) {
            return;
        }
        if (!$this->headers->apiSecret) {
            return;
        }
        if ($apiSecret != $this->headers->apiSecret) {
            return;
        }

        if ($this->headers->jwt) {
            $this->auth->loginJwt($this->headers->userUuid, $this->headers->jwt);
        } else if ($this->headers->password) {
            $this->auth->loginPassword($this->headers->userUuid, $this->headers->password);
        } else {
            return;
        }
    }
}

class AuthData {
    public $userUuid;
    public $jwt;

    function __construct($userUuid, $jwt) {
        $this->userUuid = $userUuid;
        $this->jwt = $jwt;
    }
}

class LoggedInUser {
    public $authData;

    function __construct($authData) {
        $this->authData = $authData;
    }
}

class AuthStore {
    private $passwordHashes;
    private $jwts;

    private $secret = "Catifornia1!";

    function __construct() {
        $this->passwordHashes = array(
            "dcad0298-d132-11e9-bb65-2a2ae2dbcce4" => '$2y$10$5zN9uYOHdRX0NdTprg4/h./AeYUbkUrosLoateBIhntHBjoZHZWUy'
        );

        $this->jwts = array(
            "dcad0298-d132-11e9-bb65-2a2ae2dbcce4" => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6ImRjYWQwMjk4LWQxMzItMTFlOS1iYjY1LTJhMmFlMmRiY2NlNCIsInBhc3N3b3JkX2hhc2giOiIkMnkkMTAkNXpOOXVZT0hkUlgwTmRUcHJnNFwvaC5cL0FlWVVia1Vyb3NMb2F0ZUJJaG50SEJqb1pIWldVeSJ9.SDFULSyqGr5eF6KszswZOlejEg5T2delVBsCtAjmFMY'
        );
    }

    function createUser($userUuid, $password) {
        $hash = password_hash($password, PASSWORD_DEFAULT);
    }

    function authenticateWithJwt($userUuid, $jwt) {
        if (!array_key_exists($userUuid, $this->jwts)) {
            return null;
        }
        $jwt = $this->jwts[$userUuid];

        $decodedJwt = JWT::decode($jwt, $this->secret);
        $jwtHash = $this->hashFromJwt($decodedJwt);
        if (!$jwtHash) {
            return null;
        }
        $passwordHash = $this->passwordHashes[$userUuid];
        if ($jwtHash !== $passwordHash) {
            return null;
        }
        return new AuthData($userUuid, $jwt);
    }
    function hashFromJwt($jwt) {
        return $jwt->password_hash;
    }

    function authenticateWithPassword($userUuid, $password) {
        if (!array_key_exists($userUuid, $this->passwordHashes)) {
            return null;
        }
        $hash = $this->passwordHashes[$userUuid];
        if (!password_verify($password, $hash)) {
            return null;
        }
        $token = array();
        $token['id'] = $userUuid;
        $token['password_hash'] = $hash;
        $jwt = JWT::encode($token, $this->secret);
        $this->jwts[$userUuid] = $jwt; // TODO: persist to db
        if (!$jwt) {
            return null;
        }
        return new AuthData($userUuid, $jwt);
    }
}

class AuthManager {

    private $store;

    public $user = null;

    function __construct() {
        $this->store = new AuthStore();
    }

    public function loginPassword($userUuid, $password) {
        $authData = $this->store->authenticateWithPassword($userUuid, $password);
        if (!$authData) {
            return;
        }
        $loggedInUser = new LoggedInUser($authData);
        $this->user = $loggedInUser;
    }

    public function loginJwt($userUuid, $jwt) {
        $authData = $this->store->authenticateWithJwt($userUuid, $jwt);
        if (!$authData) {
            return;
        }
        $loggedInUser = new LoggedInUser($authData);
        $this->user = $loggedInUser;
    }

}

class BaseViewController {
    public $keys;
    public $values;

    function __construct() {

    }

    function showJson() {
        $jsonDict = array_combine($this->keys, $this->values);
        $ob = json_encode ($jsonDict);
        echo $ob;
    }

    function showView() {
        $htmlKeys = array_map(
                function($key) { return '{'.$key.'}'; },
                $this->keys
        );

        $controllerName = get_class($this);
        $viewName = preg_replace('/\Controller$/', '', $controllerName);
        ob_start();
        include($viewName.'.html');
        $ob = ob_get_clean();

        echo str_replace($htmlKeys, $this->values, $ob);
    }
}

class AuthenticatedViewController extends BaseViewController {
    function __construct() {
        parent::__construct();
        if (!Application::shared()->auth->user) {
            include_once("NotAuthorized.php");
            exit;
        }
    }
}

class DoorManager {
    public $openDoor;

    function __construct() {
        $this->openDoor = array_key_exists("open_door", $_GET) ? htmlspecialchars($_GET["open_door"]) === 'true' : false;

        if ($this->openDoor) {
            $command = escapeshellcmd('/usr/bin/python /var/www/html/test.py > /dev/null &');
            shell_exec($command);
        }
    }
}

class CatHomeViewModel {
    public $output = '';

    private $doorManager;

    function __construct() {
        $this->doorManager = new DoorManager();
        $this->output = $this->doorManager->openDoor ? 'open' : 'closed';
    }
}

class CatHomeViewController extends AuthenticatedViewController {
    private $viewModel;

    function __construct() {
        parent::__construct();
        $this->viewModel = new CatHomeViewModel();
        $this->keys = array('output');
        $this->values = array($this->viewModel->output);
    }

}

$vc = new CatHomeViewController();

if (Application::shared()->json) {
    $vc->showJson();
} else {
    $vc->showView();
}

?>