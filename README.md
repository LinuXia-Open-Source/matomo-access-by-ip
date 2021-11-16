# Matomo AccessByIP Plugin

## Installation via Git

The plugin must be installed in the `matomo/plugins` directory as
`AccessByIP`:

```
git clone https://github.com/LinuXia-Open-Source/matomo-access-by-ip.git path/to/matomo/plugins/AccessByIP
```

## Description

This plugin let to configure the IPs which are permitted to login into
the Dashboard automatically, without password. These users are given a
`view` role.

If the admin can't login anymore because it gets logged in
automatically into such low privileged users, they can still login by
direct URL (clearing the cookies beforehand) at
`index.php?module=Login&action=login`

## Activation and configuration

Visit Administration / System / Plugins, activate it and configure it
like any other plugin. You need to set the IP (full or partials)
allowed to access the dashboard without any credentials and the site
IDs they are permitted to access. You can find the ID under
Administration / Websites / Manage (ID).
