<?php

$EM_CONF['shibboleth_auth'] = [
    'title' => 'Shibboleth Authentication',
    'description' => 'Shibboleth Authentication for TYPO3 CMS',
    'category' => 'services',
    'author' => 'Tamer Erdogan / Lorenz Ulrich / Jonas Renggli',
    'author_email' => 'tamer.erdogan@univie.ac.at / lorenz.ulrich@visol.ch / jonas.renggli@visol.ch',
    'author_company' => 'visol digitale Dienstleistungen GmbH',
    'state' => 'excludeFromUpdates',
    'clearCacheOnLoad' => 0,
    'version' => '5.1.0',
    'constraints' => [
        'depends' => [
            'typo3' => '10.4.0-10.4.99',
        ],
        'conflicts' => [],
        'suggests' => [],
    ],
];
