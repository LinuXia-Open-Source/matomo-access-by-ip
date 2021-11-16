<?php
/**
 * Matomo - free/libre analytics platform
 *
 * @link https://matomo.org
 * @license http://www.gnu.org/licenses/gpl-3.0.html GPL v3 or later
 */

namespace Piwik\Plugins\AccessByIP;

use Piwik\Settings\Setting;
use Piwik\Settings\FieldConfig;
use Piwik\Validators\NotEmpty;

/**
 * Defines Settings for AccessByIP.
 *
 * Usage like this:
 * $settings = new SystemSettings();
 * $settings->metric->getValue();
 * $settings->description->getValue();
 */
class SystemSettings extends \Piwik\Settings\Plugin\SystemSettings
{
    /** @var Setting */
    public $allowed_ips;

    /** @var Setting */
    public $site_ids;

    protected function init()
    {
        $this->allowed_ips = $this->createAllowedIPSetting();
        $this->site_ids = $this->createSiteIdSetting();
    }

    private function createAllowedIPSetting()
    {
        return $this->makeSetting('allowed_ips', $default = '', FieldConfig::TYPE_STRING, function (FieldConfig $field) {
            $field->title = 'Allowed IPs to be automatically login into an account with a "view" role';
            $field->uiControl = FieldConfig::UI_CONTROL_TEXT;
            $field->description = 'Comma or space separated IPs. Partial matches are supported, e.g. "199.199.", with a trailing dot (ipv4) or colon (ipv6)';
        });
    }

    private function createSiteIdSetting()
    {
        return $this->makeSetting('site_ids', $default = '', FieldConfig::TYPE_STRING, function (FieldConfig $field) {
            $field->title = 'Grant access to these site IDs';
            $field->uiControl = FieldConfig::UI_CONTROL_TEXT;
            $field->description = 'Comma or space separated site IDs';
        });
    }
}
