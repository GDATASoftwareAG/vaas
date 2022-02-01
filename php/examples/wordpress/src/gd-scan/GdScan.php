<?php
/**
 * File Scan Plugin
 * php version 7.3
 * @category Security
 * @package  GD_Scan
 * @author   G DATA CyberDefense AG <info@gdata.de>
 * @license  none www.gdata.de
 * @version  HG: 0.0.1
 * @link     www.gdata.de
 */
namespace WpGdScan;

use WpGdScan\Settings\AdminNotice;
use WpGdScan\Vaas\Client as ScanClient;

class GdScan
{
    public ScanClient $ScanClient;
    public \WpGdScan\Settings\AdminNotice $AdminNotice;
    public function __construct()
    {
        $this->ScanClient = new ScanClient();
        $this->AdminNotice = new AdminNotice();
        $this->registerFilters();
        $this->addActions();
        \add_option("gd_scan_found_malware", false);
    }

    public function addActions()
    {
        \add_action("gd_scan_single_file_action", [$this->ScanClient, "scanSingleFile"], 10, 1);
        \add_action("admin_notices", [$this->AdminNotice, "show"]);
    }

    public function registerFilters():void
    {
        \add_filter("wp_handle_upload", [$this, "scan"]);
    }

    public function scan(array $upload):array
    {
        $uploadString = var_export($upload, true);
        file_put_contents(\plugin_dir_path(__FILE__)."/log", "File Upload: $uploadString\n", FILE_APPEND);
        \wp_schedule_single_event(time()+10, 'gd_scan_single_file_action', array($upload["file"]), true);

        return $upload;
    }
}
