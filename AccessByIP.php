<?php
/**
 * Matomo - free/libre analytics platform
 *
 * @link https://matomo.org
 * @license http://www.gnu.org/licenses/gpl-3.0.html GPL v3 or later
 */

namespace Piwik\Plugins\AccessByIP;
use Piwik\IP;
use Exception;
use Piwik\FrontController;
use Piwik\Common;
use Psr\Log\LoggerInterface;
use Piwik\Container\StaticContainer;
use Piwik\Plugins\Login\Auth;
use Piwik\Plugins\Login\PasswordVerifier;
use Piwik\Session;
use Piwik\Url;
use Piwik\UrlHelper;
use Piwik\Nonce;
use Piwik\Piwik;
use Piwik\Plugins\UsersManager\Model;
use Piwik\Plugins\UsersManager\UsersManager;
use Piwik\Auth\Password;
use Piwik\Date;
use Piwik\Changes\UserChanges;

class AccessByIP extends \Piwik\Plugin
{
    private $logger;
    private $settings;
    private $user_prefix = '_AUTO_';
    public function __construct()
    {
        $this->logger = StaticContainer::get('Psr\Log\LoggerInterface');
        $this->settings = new \Piwik\Plugins\AccessByIP\SystemSettings();
        parent::__construct();
    }


    public function registerEvents()
    {
        return array(
            'Request.dispatch' => array('before' => true,
                                        'function' => 'preventDispatch'),
            'User.isNotAuthorized' => array('before' => true,
                                            'function' => 'tryWithIP'),
        );
    }
    private function check_ip($verbose) {
        $ip = IP::getIpFromHeader();
        if ($verbose) {
            $this->logger->info("IP is $ip");
        }
        $allowed = preg_split("/[\s,]+/", $this->settings->allowed_ips->getValue());
        $matched = 0;
        foreach ($allowed as $allowed_ip) {
            if (strlen($allowed_ip) > 3) {
                $last_char = substr($allowed_ip, -1);
                # partial match, ending with a dot or : (ipv6)
                if ($last_char === ':' || $last_char === '.') {
                    if (strpos($ip, $allowed_ip) === 0) {
                        if ($verbose) {
                            $this->logger->info("$ip is allowed because of partial match $allowed_ip");
                        }
                        $matched = 1;
                        break;
                    }
                }
                if ($ip === $allowed_ip) {
                    if ($verbose) {
                        $this->logger->info("$ip is allowed because of full match with $allowed_ip");
                    }
                    $matched = 1;
                    break;
                }
                if ($verbose) {
                    $this->logger->info("$ip is not allowed by $allowed_ip");
                }
            }
            else {
                if ($verbose) {
                    $this->logger->info("$allowed_ip too short, ignoring");
                }
            }
        }
        return $matched ? $ip : false;
    }

    public function tryWithIP(Exception $exception)
    {
        $frontController = FrontController::getInstance();

        # ignore ajax calls;
        if (Common::isXmlHttpRequest()) {
            return;
        }
        $valid_ip = $this->check_ip(true);
        # if found: create on the fly an user with the chosen prefix
        # and a random password, authenticate it and redirect it to
        # the home. The autenticate part is taken from the Login plugin.

        if ($valid_ip) {
            $model = StaticContainer::get('Piwik\Plugins\UsersManager\Model');
            $password = 'random' .
                        rand(1000, 1000000000000000000)
                      . rand(1000, 1000000000000000000)
                      . rand(1000, 1000000000000000000);
            UsersManager::checkPassword($password);
            $passwordTransformed = UsersManager::getPasswordHash($password);
            // the real password is the md5sum of the input.
            $this->logger->debug("Real password is $passwordTransformed");
            $passwordTransformed = StaticContainer::get('Piwik\Auth\Password')->hash($passwordTransformed);

            # username is IP + unix time
            $username = preg_replace("/[^a-z0-9\-]/i", '-', $valid_ip . '-' . time());
            $username = $this->user_prefix . $username;

            $this->logger->debug("Create $username $password $passwordTransformed");
            $model->addUser($username, $passwordTransformed, $username . '@localhost',
                            Date::now()->getDatetime());
            $model->addUserAccess($username, 'view', preg_split("/[\s,]+/", $this->settings->site_ids->getValue()));
            $this->logger->debug("Autenticating $valid_ip");
            $auth = StaticContainer::get('Piwik\Auth');
            $sessionInitializer = new \Piwik\Session\SessionInitializer();
            # $systemSettings = StaticContainer::get('Piwik\Plugins\Login\SystemSettings');
            Nonce::discardNonce('Login.login');
            $auth->setLogin($username);
            $this->logger->debug("User set");
            $auth->setPassword($password);
            $auth->authenticate();
            $this->logger->debug("Password set");
            $sessionInitializer->initSession($auth);
            $this->logger->info("Initialized");
            $user = $model->getUser($username);
            if (is_array($user)) {
                $userChanges = new UserChanges($user);
                $userChanges->markChangesAsRead();
            }
            Url::redirectToUrl('index.php');
        }
        return;
    }
    public function preventDispatch(&$module, &$action)
    {
        $username = Piwik::getCurrentUserLogin();
        # Visit by direct link with an private tab index.php?module=Login&action=login if you need to login as an admin.

        if ($username === 'anonymous' && $module === 'CoreHome' && !$action) {
            $this->logger->info("Access by IP $username: $module $action");
            $this->tryWithIP(new Exception);
            return;
        }
        if (strpos($username, $this->user_prefix) === 0) {
            # check if the IP is still in the range
            if (!$this->check_ip(false)) {
                $this->logger->info("Access by IP $username: IP is not valid anymore, logging out");
                $sessionFingerprint = new Session\SessionFingerprint();
                $sessionFingerprint->clear();
                Session::expireSessionCookie();
                return;
            }
            # prevent access to these modules to the auto users:
            if ($module === 'CoreAdminHome' && $action && $action === 'whatIsNew') {
                # permit these annoying ads
                return;
            }
            if ($module === 'UsersManager' ||
                $module === 'ScheduledReports' ||
                $module === 'PrivacyManager' ||
                $module === 'Marketplace' ||
                $module === 'Widgetize' ||
                $module === 'CoreAdminHome' ||
                $module === 'MobileMessaging')
            {
                $this->logger->info("Access by IP $username preventing: $module $action");
                throw new Exception("Access denied to part of the site");
            }
        }
    }
}
