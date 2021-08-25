<?php

namespace Visol\ShibbolethAuth\Controller;

/**
 * This file is part of the TYPO3 CMS project.
 *
 * It is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License, either version 2
 * of the License, or any later version.
 *
 * For the full copyright and license information, please read the
 * LICENSE.txt file that was distributed with this source code.
 *
 * The TYPO3 project - inspiring people to share!
 */

use TYPO3\CMS\Core\Configuration\ExtensionConfiguration;
use TYPO3\CMS\Core\Context\Context;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Core\Utility\HttpUtility;

class FrontendLoginController extends \TYPO3\CMS\Extbase\Mvc\Controller\ActionController
{

    /**
     * @var array
     */
    protected $extensionConfiguration;

    /**
     * @var string
     */
    protected $remoteUser;
    
    /**
     * The LoginController is only used to be able to dispatch the LoginConfirmed event.
     * @var LoginController
     */
    private LoginController $loginController;

    public function __construct(LoginController $loginController)
    {
        $this->loginController = $loginController;
    }

    public function initializeAction()
    {
        $this->extensionConfiguration = GeneralUtility::makeInstance(ExtensionConfiguration::class)->get('shibboleth_auth');

        if (empty($this->extensionConfiguration['remoteUser'])) {
            $this->extensionConfiguration['remoteUser'] = 'REMOTE_USER';
        }
        if (isset($_SERVER['AUTH_TYPE']) && $_SERVER['AUTH_TYPE'] === 'shibboleth') {
            $this->remoteUser = $_SERVER[$this->extensionConfiguration['remoteUser']];
        }
    }

    /**
     * @throws \TYPO3\CMS\Extbase\Mvc\Exception\StopActionException
     */
    public function indexAction()
    {
        $context = GeneralUtility::makeInstance(Context::class);

        // Login type
        $loginType = GeneralUtility::_GP('logintype');

        // URL to redirect to
        $redirectUrl = GeneralUtility::_GP('redirect_url');

        // Is user logged in?
        $userIsLoggedIn = $context->getPropertyFromAspect('frontend.user', 'isLoggedIn');

        // What to display
        if ($userIsLoggedIn) {
            $this->remoteUser = $context->getPropertyFromAspect('frontend.user', 'username');
            if (!empty($redirectUrl) || $this->getConfiguredRedirectPage()) {
                $this->forward('loginSuccess');
            } else {
                $this->forward('showLogout');
            }
        } else {
            if ($loginType === 'logout') {
                $this->forward('logoutSuccess');
            } elseif ($loginType === 'login') {
                $this->forward('showLogin');
            } else {
                $this->forward('showLogin');
            }
        }
    }

    /**
     * Display the Shibboleth login link
     */
    public function showLoginAction()
    {
        $target = GeneralUtility::getIndpEnv('TYPO3_REQUEST_URL');

        if ($this->extensionConfiguration['forceSSL'] && !GeneralUtility::getIndpEnv('TYPO3_SSL')) {
            $target = str_ireplace('http:', 'https:', $target);
            if (!preg_match('#["<>\\\]+#', $target)) {
                HttpUtility::redirect($target);
            }
        }

        // If the target page already includes an exclamation sign (e.g. non-RealURL page), we must use an ampersand here
        $target .= !strpos($target, '?') ? '?' : '&';
        $target .= 'logintype=login&pid=' . $this->extensionConfiguration['storagePid'];

        $loginHandlerUrl = $this->extensionConfiguration['loginHandler'];
        $queryStringSeparator = !strpos($loginHandlerUrl, '?') ? '?' : '&';

        $shibbolethLoginUri = $loginHandlerUrl . $queryStringSeparator . 'target=' . rawurlencode($target);
        $shibbolethLoginUri = GeneralUtility::sanitizeLocalUrl($shibbolethLoginUri);
        $this->view->assign('shibbolethLoginUri', $shibbolethLoginUri);
    }

    /**
     * Perform redirect after a successful login
     *
     * @return mixed
     */
    public function loginSuccessAction()
    {
        $this->eventDispatcher->dispatch(new LoginConfirmedEvent($this->loginController, $this->view));
        
        $redirectUrl = GeneralUtility::_GP('redirect_url');
        $targetUrl = GeneralUtility::getIndpEnv('TYPO3_REQUEST_HOST') . $redirectUrl;
        $targetUrl = GeneralUtility::sanitizeLocalUrl($targetUrl);

        $configuredRedirectPage = $this->getConfiguredRedirectPage();

        if (empty($redirectUrl) && !empty($configuredRedirectPage)) {
            $absoluteUriScheme = (bool)$this->extensionConfiguration['forceSSL'] ? 'https' : 'http';
            $targetUrl = $this->uriBuilder->setTargetPageUid((int)$configuredRedirectPage)->setAbsoluteUriScheme($absoluteUriScheme)->setCreateAbsoluteUri(true)->build();
        }
        HttpUtility::redirect($targetUrl);
    }

    /**
     * Show logout after a successful login if no redirect URL was set
     */
    public function showLogoutAction()
    {
    }

    public function logoutSuccessAction()
    {
        $redirectUrl = $this->extensionConfiguration['logoutHandler'];
        $redirectUrl = GeneralUtility::sanitizeLocalUrl($redirectUrl);
        HttpUtility::redirect($redirectUrl);
    }

    protected function getConfiguredRedirectPage()
    {
        $configuredRedirectPage = null;
        if (array_key_exists('redirectPage', $this->settings) && !empty($this->settings['redirectPage'])) {
            $configuredRedirectPage = $this->settings['redirectPage'];
        }
        return $configuredRedirectPage;
    }
}
