<?php

use TYPO3\CMS\Core\Configuration\ExtensionConfiguration;
use TYPO3\CMS\Core\Utility\ExtensionManagementUtility;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Extbase\Utility\ExtensionUtility;

defined('TYPO3') or die();

call_user_func(static function ($extKey = 'shibboleth_auth') {
    $extensionConfiguration = GeneralUtility::makeInstance(
        ExtensionConfiguration::class
    )->get($extKey);

    if ($extensionConfiguration['enableFE']) {
        $contentTypeName = ExtensionUtility::registerPlugin(
            'ShibbolethAuth',
            'Login',
            'LLL:EXT:shibboleth_auth/Resources/Private/Language/locallang_db.xlf:pluginLabel',
            'mimetypes-x-content-login',
            'forms'
        );

        // Add the FlexForm
        ExtensionManagementUtility::addPiFlexFormValue(
            '*',
            'FILE:EXT:' . $extKey . '/Configuration/FlexForm/flexform_login.xml',
            $contentTypeName
        );

        // Add the FlexForm to the show item list
        ExtensionManagementUtility::addToAllTCAtypes(
            'tt_content',
            '--div--;LLL:EXT:core/Resources/Private/Language/Form/locallang_tabs.xlf:plugin, pi_flexform',
            $contentTypeName,
            'after:palette:headers'
        );
    }
});
