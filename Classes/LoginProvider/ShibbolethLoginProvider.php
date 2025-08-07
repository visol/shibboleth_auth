<?php

namespace Visol\ShibbolethAuth\LoginProvider;

/*
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

use TYPO3\CMS\Backend\Controller\LoginController;
use TYPO3\CMS\Backend\LoginProvider\LoginProviderInterface;
use TYPO3\CMS\Core\Configuration\ExtensionConfiguration;
use TYPO3\CMS\Core\Page\PageRenderer;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Fluid\View\StandaloneView;

class ShibbolethLoginProvider implements LoginProviderInterface
{

    /**
     * @param StandaloneView $view
     * @param PageRenderer $pageRenderer
     * @param LoginController $loginController
     */
    public function render(StandaloneView $view, PageRenderer $pageRenderer, LoginController $loginController)
    {
        $extensionConfiguration = GeneralUtility::makeInstance(ExtensionConfiguration::class)->get('shibboleth_auth');

        $template = 'EXT:shibboleth_auth/Resources/Private/Templates/BackendLogin/ShibbolethLogin.html';
        if (!empty($extensionConfiguration['typo3LoginTemplate'])) {
            $template = $extensionConfiguration['typo3LoginTemplate'];
        }
        $view->setTemplatePathAndFilename(GeneralUtility::getFileAbsFileName($template));

        $target = GeneralUtility::getIndpEnv('TYPO3_REQUEST_HOST') . '/typo3/?login_status=login';
        if ($extensionConfiguration['forceSSL'] && !GeneralUtility::getIndpEnv('TYPO3_SSL')) {
            $target = str_ireplace('http:', 'https:', $target);
        }
        $loginHandlerUrl = $extensionConfiguration['loginHandler'];
        $queryStringSeparator = !strpos($loginHandlerUrl, '?') ? '?' : '&';
        $shibbolethLoginUri = $loginHandlerUrl . $queryStringSeparator . 'target=' . rawurlencode($target);
        $view->assign('shibbolethLoginUri', $shibbolethLoginUri);
    }
}
