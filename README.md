Shibboleth Authentication for TYPO3 CMS
=======================================
EXT:shibboleth_auth

Fork of the TYPO3 extension shibboleth_auth to fix performance issues and shipping with an Extbase-based Login plugin.

This extension enables the single sign-on based on Shibboleth for frontend and backend authentication. 

## Compatibility and Maintenance

This package is currently maintained for the following versions:

| TYPO3 Version | Package Version      | Branch | Maintained |
|---------------|----------------------|--------|------------|
| TYPO3 13.4.x  | 7.x (in development) | main   | Yes        |
| TYPO3 11.5.x  | 6.x                  | v11    | No         |
| TYPO3 10.4.x  | 5.x                  | v5     | No         |
| TYPO3 8.x     | 4.x                  | v4     | No         |


Prerequisites
-------------
The extension relies on values of the Shibboleth session being available within the `$_SERVER` array.

This can be achieved with either Apache or nginx, however it is easier to achieve with Apache.

Apache's Shibboleth module has to be installed on the web server before you can use this extension.

The following .htaccess rules must be added to the .htaccess file in document root:

    AuthType shibboleth
    Require shibboleth

Furthermore, a rewrite is necessary to make the Shibboleth endpoints available:

    <IfModule mod_shib>
    	RewriteRule ^(Shibhandler.*)/ - [L]
    	RewriteRule ^(Shibboleth.sso)/ - [L]
    </IfModule>

It must be the first RewriteRule in htaccess.

Installation
------------

Install this extension via `composer require visol/shibboleth-auth` and activate the extension.

After installing the extension, you have to activate the basic features in the extension's settings to be found in Admin Tools -> Settings -> Extension Configuration. 

By default, the extension will not do anything. Shibboleth authentication can be activated for frontend and backend separately. It is highly recommended to keep a browser window with an authenticated admin user open before activating and testing the backend login (see below). 

Otherwise you could lock yourself out, if your Shibboleth configuration is incorrect.

Using the Frontend login
------------------------
For frontend login you need a TYPO3 folder to store the users. To activate the frontend authentication, a plugin is available to the editors. For the plugin to work, the static TypoScript needs to be included. You can use your own templates by just overriding the paths via TypoScript constants:

    plugin.tx_shibbolethauth {
	    view {
		    templateRootPaths.10 = EXT:shibboleth_auth/Resources/Private/Templates/
		    partialRootPaths.10 = EXT:shibboleth_auth/Resources/Private/Partials/
		    layoutRootPaths.10 = EXT:shibboleth_auth/Resources/Private/Layouts/
	    }
    }

If no frontend user is logged in, a login link is displayed.

Just like other logins in TYPO3, the plugin itself provides the login, not the protection. If you want to restrict  access to the content of your login page, you have to assign the related group in the access settings. Do not assign any restrictions to the Shibboleth plugin itself! Otherwise no login redirects will be made.

In the plugin, you can also configure the redirect page after successful authentication. If a parameter `redirect_url` is passed in the URL to the login page, this parameter takes precedence over the FlexForm setting and this URL is used for a redirect on successful authentication.

Using the Backend login
------------------------
If the usage of Shibboleth for the backend login is enabled in the extension configuration, you will be presented with an additional login provider in the TYPO3 backend login form.

The `remoteUser` setting determines which backend user is looked up during the authentication process. By default, this is set to `REMOTE_USER`. This means that a user with a username identical to the value of the `REMOTE_USER` server variable must exist.

You can customize the login screen by copying `Resources/Private/Templates/BackendLogin/ShibbolethLogin.html` to another location and adjusting its contents. You can then set the configuration `typo3LoginTemplate` to this path using the `EXT:` or `FILE:` prefix.

Support
-------
If you need support setting up your TYPO3 instance with Shibboleth, you can contact us:

visol digitale Dienstleistungen GmbH, www.visol.ch
