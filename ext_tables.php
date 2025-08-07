<?php

use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Core\Configuration\ExtensionConfiguration;
use TYPO3\CMS\Extbase\Utility\ExtensionUtility;
use TYPO3\CMS\Core\Utility\ExtensionManagementUtility;
defined('TYPO3') || die();

(function ($extKey = 'shibboleth_auth') {
    $extensionConfiguration = GeneralUtility::makeInstance(
        ExtensionConfiguration::class
    )->get($extKey);

    if ($extensionConfiguration['enableFE']) {
        // TypoScript Configuration
        ExtensionManagementUtility::addStaticFile(
            $extKey,
            'Configuration/TypoScript',
            'Shibboleth Authentication'
        );
    }
})();
