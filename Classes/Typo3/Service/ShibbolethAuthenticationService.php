<?php

namespace Visol\ShibbolethAuth\Typo3\Service;

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

use Symfony\Component\HttpFoundation\Cookie;
use TYPO3\CMS\Core\Core\Environment;
use TYPO3\CMS\Core\Http\ApplicationType;
use TYPO3\CMS\Core\Context\Context;
use TYPO3\CMS\Backend\Exception;
use TYPO3\CMS\Core\Authentication\AbstractAuthenticationService;
use TYPO3\CMS\Core\Authentication\AbstractUserAuthentication;
use TYPO3\CMS\Core\Configuration\ExtensionConfiguration;
use TYPO3\CMS\Core\Crypto\PasswordHashing\PasswordHashFactory;
use TYPO3\CMS\Core\Crypto\Random;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;
use TYPO3\CMS\Core\Utility\GeneralUtility;

class ShibbolethAuthenticationService extends AbstractAuthenticationService
{

    protected string $extKey = 'shibboleth_auth';

    protected array $extensionConfiguration = [];

    protected ?string $remoteUser = '';

    public function init(): bool
    {
        $this->extensionConfiguration = GeneralUtility::makeInstance(ExtensionConfiguration::class)->get(
            'shibboleth_auth'
        );
        if (empty($this->extensionConfiguration['remoteUser'])) {
            $this->extensionConfiguration['remoteUser'] = 'REMOTE_USER';
        }
        if (empty($this->extensionConfiguration['displayName'])) {
            $this->extensionConfiguration['displayName'] = 'displayName';
        }
        $this->remoteUser = $_SERVER[$this->extensionConfiguration['remoteUser']];
        return parent::init();
    }

    /**
     * Initialize authentication service
     *
     * @param string $mode Subtype of the service which is used to call the service.
     * @param array $loginData Submitted login form data
     * @param array $authInfo Information array. Holds submitted form data etc.
     * @param AbstractUserAuthentication $pObj Parent object
     */
    public function initAuth($mode, $loginData, $authInfo, $pObj): void
    {
        if (Environment::isCli()) {
            parent::initAuth($mode, $loginData, $authInfo, $pObj);
        }

        // bypass Shibboleth login if enableFE is 0
        if (!($this->extensionConfiguration['enableFE']) && ApplicationType::fromRequest($GLOBALS['TYPO3_REQUEST'])->isFrontend()) {
            parent::initAuth($mode, $loginData, $authInfo, $pObj);
        }

        $this->login = $loginData;
        if (empty($this->login['uname']) && empty($this->remoteUser)) {
            parent::initAuth($mode, $loginData, $authInfo, $pObj);
        } else {
            $loginData['status'] = 'login';
            parent::initAuth($mode, $loginData, $authInfo, $pObj);
        }
    }

    public function getUser()
    {
        $user = false;
        if ($this->login['status'] == 'login' && $this->isShibbolethLogin() && empty($this->login['uname'])) {
            $user = $this->fetchUserRecord($this->remoteUser);
            if (!is_array($user) || empty($user)) {
                if ($this->isLoginTypeFrontend(
                    ) && !empty($this->remoteUser) && $this->extensionConfiguration['enableAutoImport']) {
                    $this->importFrontendUser();
                } else {
                    $user = false;
                    // Failed login attempt (no username found)
                    $this->writelog(
                        255,
                        3,
                        3,
                        2,
                        "Login attempt from %s (%s), username '%s' not found!",
                        [$this->authInfo['REMOTE_ADDR'], $this->authInfo['REMOTE_HOST'], $this->remoteUser]
                    );
                }
            } else {
                if ($this->isLoginTypeFrontend() && $this->extensionConfiguration['enableAutoImport']) {
                    $this->updateFrontendUser();
                }
            }
            if ($this->isLoginTypeFrontend()) {
                // The frontend user was updated, it should be fetched again
                $user = $this->fetchUserRecord($this->remoteUser);
            }
        }

        // Deny Backend login for non-Shibboleth authentication if onlyShibbolethFunc is set
        if (!(Environment::isCli()) && $this->authInfo['loginType'] === 'BE' && $this->extensionConfiguration['onlyShibbolethBE'] && empty($user)) {
            // Implement your own error page
            if (is_array($GLOBALS['TYPO3_CONF_VARS']['EXTCONF'][$this->extKey]['onlyShibbolethFunc'])) {
                foreach ($GLOBALS['TYPO3_CONF_VARS']['EXTCONF'][$this->extKey]['onlyShibbolethFunc'] as $_classRef) {
                    $_procObj = GeneralUtility::makeInstance($_classRef);
                    $_procObj->onlyShibbolethFunc($this->remoteUser);
                }
            } else {
                throw new Exception(
                    'Login without Shibboleth is not permitted.',
                    1616498840
                );
            }
            foreach ($_COOKIE as $key => $val) {
                unset($_COOKIE[$key]);
            }
            exit;
        }

        return $user;
    }

    /**
     * Authenticate a user (Check various conditions for the user that might invalidate its authentication, eg. password match, domain, IP, etc.)
     *
     * Will return one of following authentication status codes:
     *  - 0 - authentication failure
     *  - 100 - just go on. User is not authenticated but there is still no reason to stop
     *  - 200 - the service was able to authenticate the user
     */
    public function authUser(array $user): int
    {
        $OK = 100;

        if (Environment::isCli()) {
            $OK = 100;
        } else {
            if (($this->isLoginTypeFrontend()) && !empty($this->login['uname'])) {
                $OK = 100;
            } else {
                if ($this->isShibbolethLogin() && !empty($user) && ($this->remoteUser === $user[$this->authInfo['db_user']['username_column']])) {
                    $OK = 200;
                    if ($user['lockToDomain'] && $user['lockToDomain'] !== $this->authInfo['HTTP_HOST']) {
                        // Lock domain didn't match, so error:
                        if ($this->writeAttemptLog) {
                            $this->writelog(
                                255,
                                3,
                                3,
                                1,
                                "Login attempt from %s (%s), username '%s', locked domain '%s' did not match '%s'!",
                                [
                                    $this->authInfo['REMOTE_ADDR'],
                                    $this->authInfo['REMOTE_HOST'],
                                    $user[$this->authInfo['db_user']['username_column']],
                                    $user['lockToDomain'],
                                    $this->authInfo['HTTP_HOST']
                                ]
                            );
                        }
                        $OK = 0;
                    }
                }
            }
        }

        return $OK;
    }

    /**
     * Creates a new FE user from the current Shibboleth data
     */
    protected function importFrontendUser(): void
    {
        $this->writelog(255, 3, 3, 2, 'Importing user %s.', [$this->remoteUser]);
        $this->getDatabaseConnectionForFrontendUsers()->insert(
            $this->authInfo['db_user']['table'],
            [
                'crdate' => time(),
                'tstamp' => time(),
                'pid' => $this->extensionConfiguration['storagePid'],
                'username' => $this->remoteUser,
                'password' => $this->getRandomPassword(),
                'email' => $this->getServerVar($this->extensionConfiguration['mail']),
                'name' => $this->getServerVar($this->extensionConfiguration['displayName']),
                'usergroup' => $this->getFEUserGroups(),
            ]
        );
    }

    /**
     * Updates an existing FE user with the current data provided by Shibboleth
     */
    protected function updateFrontendUser(): void
    {
        $this->writelog(255, 3, 3, 2, 'Updating user %s.', [$this->remoteUser]);
        $this->getDatabaseConnectionForFrontendUsers()->update(
            $this->authInfo['db_user']['table'], // table
            [
                'tstamp' => time(),
                'username' => $this->remoteUser,
                'password' => $this->getRandomPassword(),
                'email' => $this->getServerVar($this->extensionConfiguration['mail']),
                'name' => $this->getServerVar($this->extensionConfiguration['displayName']),
                'usergroup' => $this->getFEUserGroups(),
            ],
            [
                'username' => $this->remoteUser,
                'pid' => $this->extensionConfiguration['storagePid'],
            ]
        );
    }

    /**
     * Fetches all affiliations from the Shibboleth user
     * Creates a user group for each affiliation if it doesn't exist yet and returns a list of all user groups to be
     * assigned to the user
     *
     * @return string
     */
    protected function getFEUserGroups()
    {
        $frontendUserGroupUids = [];
        $eduPersonAffiliation = $this->getServerVar($this->extensionConfiguration['eduPersonAffiliation']);

        if (empty($eduPersonAffiliation)) {
            $eduPersonAffiliation = 'member';
        }
        if (!empty($eduPersonAffiliation)) {
            $affiliation = explode(';', $eduPersonAffiliation);
            array_walk($affiliation, function(&$v){$v = preg_replace('/@.*/', '', $v);});

            // insert the affiliations in fe_groups if they are not there.
            foreach ($affiliation as $title) {
                $frontendUserGroupUids[] = $this->getOrCreateFrontendUserGroupByTitleAndReturnUid($title);
            }
        }

        // Hook for any additional fe_groups
        if (is_array($GLOBALS['TYPO3_CONF_VARS']['EXTCONF'][$this->extKey]['getFEUserGroups'])) {
            foreach ($GLOBALS['TYPO3_CONF_VARS']['EXTCONF'][$this->extKey]['getFEUserGroups'] as $_classRef) {
                $_procObj = GeneralUtility::makeInstance($_classRef);
                $frontendUserGroupUids = $_procObj->getFEUserGroups($frontendUserGroupUids);
            }
        }
        return implode(',', $frontendUserGroupUids);
    }

    /**
     * @return boolean
     */
    protected function isShibbolethLogin(): bool
    {
        $isShibbolethLogin = isset($_SERVER['AUTH_TYPE']) && (strtolower($_SERVER['AUTH_TYPE']) === 'shibboleth');
        if (!$isShibbolethLogin) {
            // In some cases, no AUTH_TYPE is set. We then fall back to find out if Shib_Session_ID is set
            $isShibbolethLogin = isset($_SERVER['Shib_Session_ID']) || isset($_SERVER['REDIRECT_Shib_Session_ID']);
        }
        return $isShibbolethLogin && !empty($this->remoteUser);
    }

    /**
     * Returns the requested variable from $_SERVER
     *
     * Falls back to the prefixed version (e.g. $_SERVER['REDIRECT_affiliation'] instead of $_SERVER['affiliation'] if needed.
     * This is necessary if there was an internal redirect after authentication.
     */
    protected function getServerVar(string $key, string $prefix = 'REDIRECT_'): ?string
    {
        if (isset($_SERVER[$key])) {
            return $_SERVER[$key];
        } else {
            if (isset($_SERVER[$prefix . $key])) {
                return $_SERVER[$prefix . $key];
            } else {
                foreach ($_SERVER as $k => $v) {
                    if ($key == str_replace($prefix, '', $k)) {
                        return $v;
                    }
                }
            }
        }
        return null;
    }

    protected function getRandomPassword(): string
    {
        $randomPassword = GeneralUtility::makeInstance(Random::class)->generateRandomBytes(32);
        $hashInstance = GeneralUtility::makeInstance(PasswordHashFactory::class)->getDefaultHashInstance('FE');
        return $hashInstance->getHashedPassword($randomPassword);
    }

    protected function isLoginTypeFrontend(): bool
    {
        return $this->authInfo['loginType'] === 'FE';
    }

    protected function getDatabaseConnectionForFrontendUsers(): Connection
    {
        return $this->getDatabaseConnectionPool()->getConnectionForTable($this->authInfo['db_user']['table']);
    }

    /**
     * Looks up a frontend user groups with the same title as an affiliation
     * If it exists, return uid, if not, create one and return uid
     */
    protected function getOrCreateFrontendUserGroupByTitleAndReturnUid(string $title): int
    {
        $frontendUserGroupTable = 'fe_groups';

        /** @var QueryBuilder $queryBuilder */
        $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable(
            $frontendUserGroupTable
        );
        $recordData = $queryBuilder->select('*')->from($frontendUserGroupTable)->where(
                $queryBuilder->expr()->eq('title', $queryBuilder->createNamedParameter($title)),
                $queryBuilder->expr()->eq('pid', $this->extensionConfiguration['storagePid']),
            )->executeQuery()->fetchAssociative();

        if ($recordData) {
            return $recordData['uid'];
        }

        $databaseConnection = $this->getDatabaseConnectionPool()->getConnectionForTable(
            $frontendUserGroupTable
        );
        $databaseConnection->insert(
            $frontendUserGroupTable,
            [
                'pid' => $this->extensionConfiguration['storagePid'],
                'title' => $title,
            ]
        );
        return (int)$databaseConnection->lastInsertId();
    }

    protected function getDatabaseConnectionPool(): ConnectionPool
    {
        return GeneralUtility::makeInstance(ConnectionPool::class);
    }

}
