<?php
/**
 * Plugin Name: File Scan Plugin
 * Version: 0.0.1
 * Requires PHP: 7.3
 * Plugin URI: www.gdata.de
 * 
 * @category Security
 * @package  GD_Scan
 * @author   G DATA CyberDefense AG <info@gdata.de>
 * @license  none www.gdata.de
 * @link     www.gdata.de
 */
namespace WpGdScan;

require_once dirname(__FILE__)."/vendor/autoload.php";

$gdScan = new GdScan();
