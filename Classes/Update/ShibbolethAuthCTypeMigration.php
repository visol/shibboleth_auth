<?php

declare(strict_types=1);

namespace Visol\ShibbolethAuth\Update;

use TYPO3\CMS\Install\Attribute\UpgradeWizard;
use TYPO3\CMS\Install\Updates\AbstractListTypeToCTypeUpdate;

#[UpgradeWizard('visolShibbolethAuthCTypeMigration')]
final class ShibbolethAuthCTypeMigration extends AbstractListTypeToCTypeUpdate
{
    public function getTitle(): string
    {
        return 'Migrate "shibboleth_auth" plugins to content elements.';
    }

    public function getDescription(): string
    {
        return 'The "shibboleth_auth" plugins are now registered as content element. Update migrates existing records and backend user permissions.';
    }

    /**
     * @return array<string, string>
     */
    protected function getListTypeToCTypeMapping(): array
    {
        return [
            'shibbolethauth_login' => 'shibbolethauth_login',
        ];
    }
}
