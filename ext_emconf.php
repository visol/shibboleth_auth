<?php

$EM_CONF[$_EXTKEY] = [
    'title' => 'Shibboleth Authentication',
    'description' => 'Shibboleth Single Sign On Authentication (BE & FE). The FE users will be imported automatically into the configured storage pid.',
    'category' => 'services',
    'shy' => 0,
    'version' => '4.3.0',
    'dependencies' => '',
    'conflicts' => '',
    'priority' => '',
    'loadOrder' => '',
    'module' => '',
    'state' => 'excludeFromUpdates',
    'uploadfolder' => 0,
    'createDirs' => '',
    'modify_tables' => '',
    'clearcacheonload' => 0,
    'lockType' => '',
    'author' => 'Tamer Erdogan / Lorenz Ulrich / Jonas Renggli',
    'author_email' => 'tamer.erdogan@univie.ac.at / lorenz.ulrich@visol.ch / jonas.renggli@visol.ch',
    'author_company' => '',
    'CGLcompliance' => '',
    'CGLcompliance_note' => '',
    'constraints' => [
        'depends' => [
            'typo3' => '8.7.0-8.99.99',
        ],
        'conflicts' => [],
        'suggests' => [],
    ],
];
