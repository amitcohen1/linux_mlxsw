/* SPDX-License-Identifier: GPL-2.0-only */

#include <uapi/linux/ethtool.h>

void ethnl_module_fw_flash_ntf_err(struct net_device *dev,
				   const char *status_msg);
void ethnl_module_fw_flash_ntf_start(struct net_device *dev);
void ethnl_module_fw_flash_ntf_complete(struct net_device *dev);
void ethnl_module_fw_flash_ntf_in_progress(struct net_device *dev, u64 done,
					   u64 total);

/**
 * struct ethtool_module_fw_flash_params - module firmware flashing parameters
 * @file_name: Firmware image file name.
 * @password: Module password. Only valid when @pass_valid is set.
 * @password_valid: Whether the module password is valid or not.
 */
struct ethtool_module_fw_flash_params {
	const char *file_name;
	u32 password;
	u8 password_valid:1;
};
