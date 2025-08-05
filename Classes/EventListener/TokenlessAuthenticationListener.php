<?php

declare(strict_types=1);

namespace Visol\ShibbolethAuth\EventListener;

use TYPO3\CMS\Core\Authentication\Event\BeforeRequestTokenProcessedEvent;
use TYPO3\CMS\Core\Security\RequestToken;

final class TokenlessAuthenticationListener
{
    public function __invoke(BeforeRequestTokenProcessedEvent $event): void
    {
        $user = $event->getUser();
        $requestToken = $event->getRequestToken();
        // fine, there is a valid request token
        if ($requestToken instanceof RequestToken) {
            return;
        }
        // TODO: Consider using this only when we have a Shibboleth Login
        $event->setRequestToken(
            RequestToken::create('core/user-auth/' . strtolower($user->loginType)),
        );
    }
}
