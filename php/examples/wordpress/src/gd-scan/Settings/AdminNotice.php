<?php

namespace WpGdScan\Settings;

class AdminNotice
{
    private function shouldShow(): bool
    {
        $malwareFound = \get_option("gd_scan_found_malware", false);
        if ($malwareFound) {
            $currentUser = \wp_get_current_user();
            if (in_array('administrator', $currentUser->roles)) {
                return true;
            }
        }
        return false;
    }

    public function show(): void
    {
        if ($this->shouldShow()) {
            file_put_contents(
                \plugin_dir_path(__FILE__)."/log",
                "Malware found! But I can't tell you where yet. \n",
                FILE_APPEND
            );
            \update_option("gd_scan_found_malware", false);
            echo '<div class="notice notice-error is-dismissible">
                <p>MALWARE DETECTED</p>
            </div>';
        }
    }
}
