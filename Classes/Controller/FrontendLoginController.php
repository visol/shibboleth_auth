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

use Psr\Http\Message\ResponseInterface;
use TYPO3\CMS\Core\Crypto\HashService;
use TYPO3\CMS\Extbase\Http\ForwardResponse;
use TYPO3\CMS\Extbase\Mvc\Controller\ActionController;
use TYPO3\CMS\Core\Configuration\ExtensionConfiguration;
use TYPO3\CMS\Core\Context\Context;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Frontend\Authentication\FrontendUserAuthentication;

class FrontendLoginController extends ActionController
{

    protected array $extensionConfiguration = [];

    protected string $remoteUser = '';

    public function initializeAction(): void
    {
        $this->extensionConfiguration = GeneralUtility::makeInstance(ExtensionConfiguration::class)->get(
            'shibboleth_auth'
        );

        if (empty($this->extensionConfiguration['remoteUser'])) {
            $this->extensionConfiguration['remoteUser'] = 'REMOTE_USER';
        }
        if (isset($_SERVER['AUTH_TYPE']) && $_SERVER['AUTH_TYPE'] === 'shibboleth') {
            $this->remoteUser = $_SERVER[$this->extensionConfiguration['remoteUser']];
        }
    }

    public function indexAction(): ResponseInterface
    {
        $context = GeneralUtility::makeInstance(Context::class);

        // Login type
        $loginType = $this->request->getParsedBody()['logintype'] ?? $this->request->getQueryParams(
        )['logintype'] ?? null;

        // URL to redirect to
        $redirectUrl = $this->request->getParsedBody()['redirect_url'] ?? $this->request->getQueryParams(
        )['redirect_url'] ?? null;
        $referer = $this->request->getParsedBody()['referer'] ?? $this->request->getQueryParams()['referer'] ?? null;

        // Is user logged in?
        $userIsLoggedIn = $context->getPropertyFromAspect('frontend.user', 'isLoggedIn');

        // What to display
        if ($userIsLoggedIn) {
            $this->remoteUser = $context->getPropertyFromAspect('frontend.user', 'username');
            if (!empty($redirectUrl) || !empty($referer) || $this->getConfiguredRedirectPage()) {
                return new ForwardResponse('loginSuccess');
            } else {
                return new ForwardResponse('showLogout');
            }
        } else {
            if ($loginType === 'logout') {
                return new ForwardResponse('logoutSuccess');
            } elseif ($loginType === 'login') {
                return new ForwardResponse('showLogin');
            } else {
                return new ForwardResponse('showLogin');
            }
        }
    }

    /**
     * Display the Shibboleth login link
     */
    public function showLoginAction(): ResponseInterface
    {
        $target = GeneralUtility::getIndpEnv('TYPO3_REQUEST_URL');

        if ($this->extensionConfiguration['forceSSL'] && !GeneralUtility::getIndpEnv('TYPO3_SSL')) {
            $target = str_ireplace('http:', 'https:', $target);
            if (!preg_match('#["<>\\\]+#', $target)) {
                return $this->redirectToUri($target);
            }
        }

        // If the target page already includes an exclamation sign (e.g. non-speaking URL), we must use an ampersand here
        $target .= !strpos($target, '?') ? '?' : '&';
        $target .= 'logintype=login&pid=' . $this->resolveLoginStoragePid();

        $loginHandlerUrl = $this->extensionConfiguration['loginHandler'];
        $queryStringSeparator = !strpos($loginHandlerUrl, '?') ? '?' : '&';

        $shibbolethLoginUri = $loginHandlerUrl . $queryStringSeparator . 'target=' . rawurlencode($target);
        $shibbolethLoginUri = GeneralUtility::sanitizeLocalUrl($shibbolethLoginUri);
        $this->view->assign('shibbolethLoginUri', $shibbolethLoginUri);
        return $this->htmlResponse();
    }

    /**
     * Perform redirect after a successful login
     *
     * @return mixed
     */
    public function loginSuccessAction(): ResponseInterface
    {
        $redirectUrl = $this->request->getParsedBody()['redirect_url'] ?? $this->request->getQueryParams(
        )['redirect_url'] ?? null;
        $referer = $this->request->getParsedBody()['referer'] ?? $this->request->getQueryParams(
        )['referer'] ?? null;

        $targetUrl = $redirectUrl ?: $referer;
        $typo3RequestHost = GeneralUtility::getIndpEnv('TYPO3_REQUEST_HOST');
        $targetUrl = !str_starts_with($targetUrl, $typo3RequestHost) ? $typo3RequestHost . $targetUrl : $targetUrl;
        $targetUrl = GeneralUtility::sanitizeLocalUrl($targetUrl);

        $configuredRedirectPage = $this->getConfiguredRedirectPage();

        if (empty($redirectUrl) && empty($referer) && !empty($configuredRedirectPage)) {
            $absoluteUriScheme = (bool)$this->extensionConfiguration['forceSSL'] ? 'https' : 'http';
            $targetUrl = $this->uriBuilder->setTargetPageUid((int)$configuredRedirectPage)->setAbsoluteUriScheme(
                $absoluteUriScheme
            )->setCreateAbsoluteUri(true)->build();
        }
        return $this->redirectToUri($targetUrl);
    }

    /**
     * Show logout after a successful login if no redirect URL was set
     */
    public function showLogoutAction(): ResponseInterface
    {
        return $this->htmlResponse();
    }

    public function logoutSuccessAction(): ResponseInterface
    {
        $redirectUrl = $this->extensionConfiguration['logoutHandler'];
        $redirectUrl = GeneralUtility::sanitizeLocalUrl($redirectUrl);
        return $this->redirectToUri($redirectUrl);
    }

    protected function getConfiguredRedirectPage()
    {
        $configuredRedirectPage = null;
        if (array_key_exists('redirectPage', $this->settings) && !empty($this->settings['redirectPage'])) {
            $configuredRedirectPage = $this->settings['redirectPage'];
        }
        return $configuredRedirectPage;
    }

    /**
     * Resolves the login storage pid value to be used during an HTTP request.
     */
    protected function resolveLoginStoragePid(): string
    {
        $storagePid = (string)($this->extensionConfiguration['storagePid'] ?? '0');
        $hashService = GeneralUtility::makeInstance(HashService::class);
        return sprintf(
            '%s@%s',
            $storagePid,
            $hashService->hmac($storagePid, FrontendUserAuthentication::class)
        );
    }

}
