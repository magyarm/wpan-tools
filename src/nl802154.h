#ifndef __NL802154_H
#define __NL802154_H
/*
 * 802.15.4 netlink interface public header
 *
 * Copyright 2014 Alexander Aring <aar@pengutronix.de>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

#define NL802154_GENL_NAME "nl802154"

enum nl802154_commands {
/* don't change the order or add anything between, this is ABI! */
/* currently we don't shipping this file via uapi, ignore the above one */
	NL802154_CMD_UNSPEC,

	NL802154_CMD_GET_WPAN_PHY,		/* can dump */
	NL802154_CMD_SET_WPAN_PHY,
	NL802154_CMD_NEW_WPAN_PHY,
	NL802154_CMD_DEL_WPAN_PHY,

	NL802154_CMD_GET_INTERFACE,		/* can dump */
	NL802154_CMD_SET_INTERFACE,
	NL802154_CMD_NEW_INTERFACE,
	NL802154_CMD_DEL_INTERFACE,

	NL802154_CMD_SET_CHANNEL,

	NL802154_CMD_SET_PAN_ID,
	NL802154_CMD_SET_SHORT_ADDR,

	NL802154_CMD_SET_TX_POWER,
	NL802154_CMD_SET_CCA_MODE,
	NL802154_CMD_SET_CCA_ED_LEVEL,

	NL802154_CMD_SET_MAX_FRAME_RETRIES,

	NL802154_CMD_SET_BACKOFF_EXPONENT,
	NL802154_CMD_SET_MAX_CSMA_BACKOFFS,

	NL802154_CMD_SET_LBT_MODE,

	NL802154_CMD_ED_SCAN_REQ,
	NL802154_CMD_ED_SCAN_CNF,

	NL802154_CMD_ASSOC_REQ,
	NL802154_CMD_ASSOC_IND,
	NL802154_CMD_ASSOC_RSP,
	NL802154_CMD_ASSOC_CNF,

	/* add new commands above here */

	/* used to define NL802154_CMD_MAX below */
	__NL802154_CMD_AFTER_LAST,
	NL802154_CMD_MAX = __NL802154_CMD_AFTER_LAST - 1
};

enum nl802154_attrs {
/* don't change the order or add anything between, this is ABI! */
/* currently we don't shipping this file via uapi, ignore the above one */
	NL802154_ATTR_UNSPEC,

	NL802154_ATTR_WPAN_PHY,
	NL802154_ATTR_WPAN_PHY_NAME,

	NL802154_ATTR_IFINDEX,
	NL802154_ATTR_IFNAME,
	NL802154_ATTR_IFTYPE,

	NL802154_ATTR_WPAN_DEV,

	NL802154_ATTR_PAGE,
	NL802154_ATTR_CHANNEL,

	NL802154_ATTR_PAN_ID,
	NL802154_ATTR_SHORT_ADDR,

	NL802154_ATTR_TX_POWER,

	NL802154_ATTR_CCA_MODE,
	NL802154_ATTR_CCA_OPT,
	NL802154_ATTR_CCA_ED_LEVEL,

	NL802154_ATTR_MAX_FRAME_RETRIES,

	NL802154_ATTR_MAX_BE,
	NL802154_ATTR_MIN_BE,
	NL802154_ATTR_MAX_CSMA_BACKOFFS,

	NL802154_ATTR_LBT_MODE,

	NL802154_ATTR_GENERATION,

	NL802154_ATTR_CHANNELS_SUPPORTED,
	NL802154_ATTR_SUPPORTED_CHANNEL,

	NL802154_ATTR_EXTENDED_ADDR,

	NL802154_ATTR_WPAN_PHY_CAPS,

	NL802154_ATTR_SUPPORTED_COMMANDS,

	NL802154_ATTR_SCAN_STATUS,
	NL802154_ATTR_SCAN_TYPE,
	NL802154_ATTR_SCAN_DURATION,
	NL802154_ATTR_SCAN_RESULT_LIST_SIZE,
	NL802154_ATTR_SCAN_ENERGY_DETECT_LIST,
	NL802154_ATTR_SCAN_ENERGY_DETECT_LIST_ENTRY,
	NL802154_ATTR_SCAN_DETECTED_CATEGORY,

	NL802154_ATTR_SEC_LEVEL,
	NL802154_ATTR_SEC_KEY_ID_MODE,
	NL802154_ATTR_SEC_KEY_SOURCE,
	NL802154_ATTR_SEC_KEY_SOURCE_ENTRY,
	NL802154_ATTR_SEC_KEY_INDEX,

	NL802154_ATTR_ADDR_MODE,

	NL802154_ATTR_ASSOC_CAP_INFO,
	NL802154_ATTR_ASSOC_STATUS,

	/* add attributes here, update the policy in nl802154.c */

	__NL802154_ATTR_AFTER_LAST,
	NL802154_ATTR_MAX = __NL802154_ATTR_AFTER_LAST - 1
};

enum nl802154_iftype {
	/* for backwards compatibility TODO */
	NL802154_IFTYPE_UNSPEC = -1,

	NL802154_IFTYPE_NODE,
	NL802154_IFTYPE_MONITOR,
	NL802154_IFTYPE_COORD,

	/* keep last */
	NUM_NL802154_IFTYPES,
	NL802154_IFTYPE_MAX = NUM_NL802154_IFTYPES - 1
};

/**
 * enum nl802154_wpan_phy_capability_attr - wpan phy capability attributes
 *
 * @__NL802154_CAP_ATTR_INVALID: attribute number 0 is reserved
 * @NL802154_CAP_ATTR_CHANNELS: a nested attribute for nl802154_channel_attr
 * @NL802154_CAP_ATTR_TX_POWERS: a nested attribute for
 *	nl802154_wpan_phy_tx_power
 * @NL802154_CAP_ATTR_MIN_CCA_ED_LEVEL: minimum value for cca_ed_level
 * @NL802154_CAP_ATTR_MAX_CCA_ED_LEVEL: maxmimum value for cca_ed_level
 * @NL802154_CAP_ATTR_CCA_MODES: nl802154_cca_modes flags
 * @NL802154_CAP_ATTR_CCA_OPTS: nl802154_cca_opts flags
 * @NL802154_CAP_ATTR_MIN_MINBE: minimum of minbe value
 * @NL802154_CAP_ATTR_MAX_MINBE: maximum of minbe value
 * @NL802154_CAP_ATTR_MIN_MAXBE: minimum of maxbe value
 * @NL802154_CAP_ATTR_MAX_MINBE: maximum of maxbe value
 * @NL802154_CAP_ATTR_MIN_CSMA_BACKOFFS: minimum of csma backoff value
 * @NL802154_CAP_ATTR_MAX_CSMA_BACKOFFS: maximum of csma backoffs value
 * @NL802154_CAP_ATTR_MIN_FRAME_RETRIES: minimum of frame retries value
 * @NL802154_CAP_ATTR_MAX_FRAME_RETRIES: maximum of frame retries value
 * @NL802154_CAP_ATTR_IFTYPES: nl802154_iftype flags
 * @NL802154_CAP_ATTR_LBT: nl802154_supported_bool_states flags
 * @NL802154_CAP_ATTR_MAX: highest cap attribute currently defined
 * @__NL802154_CAP_ATTR_AFTER_LAST: internal use
 */
enum nl802154_wpan_phy_capability_attr {
	__NL802154_CAP_ATTR_INVALID,

	NL802154_CAP_ATTR_IFTYPES,

	NL802154_CAP_ATTR_CHANNELS,
	NL802154_CAP_ATTR_TX_POWERS,

	NL802154_CAP_ATTR_CCA_ED_LEVELS,
	NL802154_CAP_ATTR_CCA_MODES,
	NL802154_CAP_ATTR_CCA_OPTS,

	NL802154_CAP_ATTR_MIN_MINBE,
	NL802154_CAP_ATTR_MAX_MINBE,

	NL802154_CAP_ATTR_MIN_MAXBE,
	NL802154_CAP_ATTR_MAX_MAXBE,

	NL802154_CAP_ATTR_MIN_CSMA_BACKOFFS,
	NL802154_CAP_ATTR_MAX_CSMA_BACKOFFS,

	NL802154_CAP_ATTR_MIN_FRAME_RETRIES,
	NL802154_CAP_ATTR_MAX_FRAME_RETRIES,

	NL802154_CAP_ATTR_LBT,

	/* keep last */
	__NL802154_CAP_ATTR_AFTER_LAST,
	NL802154_CAP_ATTR_MAX = __NL802154_CAP_ATTR_AFTER_LAST - 1
};

/**
 * enum nl802154_cca_modes - cca modes
 *
 * @__NL802154_CCA_INVALID: cca mode number 0 is reserved
 * @NL802154_CCA_ENERGY: Energy above threshold
 * @NL802154_CCA_CARRIER: Carrier sense only
 * @NL802154_CCA_ENERGY_CARRIER: Carrier sense with energy above threshold
 * @NL802154_CCA_ALOHA: CCA shall always report an idle medium
 * @NL802154_CCA_UWB_SHR: UWB preamble sense based on the SHR of a frame
 * @NL802154_CCA_UWB_MULTIPLEXED: UWB preamble sense based on the packet with
 *	the multiplexed preamble
 * @__NL802154_CCA_ATTR_AFTER_LAST: Internal
 * @NL802154_CCA_ATTR_MAX: Maximum CCA attribute number
 */
enum nl802154_cca_modes {
	__NL802154_CCA_INVALID,
	NL802154_CCA_ENERGY,
	NL802154_CCA_CARRIER,
	NL802154_CCA_ENERGY_CARRIER,
	NL802154_CCA_ALOHA,
	NL802154_CCA_UWB_SHR,
	NL802154_CCA_UWB_MULTIPLEXED,

	/* keep last */
	__NL802154_CCA_ATTR_AFTER_LAST,
	NL802154_CCA_ATTR_MAX = __NL802154_CCA_ATTR_AFTER_LAST - 1
};

/**
 * enum nl802154_cca_opts - additional options for cca modes
 *
 * @NL802154_CCA_OPT_ENERGY_CARRIER_OR: NL802154_CCA_ENERGY_CARRIER with OR
 * @NL802154_CCA_OPT_ENERGY_CARRIER_AND: NL802154_CCA_ENERGY_CARRIER with AND
 */
enum nl802154_cca_opts {
	NL802154_CCA_OPT_ENERGY_CARRIER_AND,
	NL802154_CCA_OPT_ENERGY_CARRIER_OR,

	/* keep last */
	__NL802154_CCA_OPT_ATTR_AFTER_LAST,
	NL802154_CCA_OPT_ATTR_MAX = __NL802154_CCA_OPT_ATTR_AFTER_LAST - 1
};

/**
 * enum nl802154_supported_bool_states - bool states for bool capability entry
 *
 * @NL802154_SUPPORTED_BOOL_FALSE: indicates to set false
 * @NL802154_SUPPORTED_BOOL_TRUE: indicates to set true
 * @__NL802154_SUPPORTED_BOOL_INVALD: reserved
 * @NL802154_SUPPORTED_BOOL_BOTH: indicates to set true and false
 * @__NL802154_SUPPORTED_BOOL_AFTER_LAST: Internal
 * @NL802154_SUPPORTED_BOOL_MAX: highest value for bool states
 */
enum nl802154_supported_bool_states {
	NL802154_SUPPORTED_BOOL_FALSE,
	NL802154_SUPPORTED_BOOL_TRUE,
	/* to handle them in a mask */
	__NL802154_SUPPORTED_BOOL_INVALD,
	NL802154_SUPPORTED_BOOL_BOTH,

	/* keep last */
	__NL802154_SUPPORTED_BOOL_AFTER_LAST,
	NL802154_SUPPORTED_BOOL_MAX = __NL802154_SUPPORTED_BOOL_AFTER_LAST - 1
};

//Bringing in the scan type defines from ieee802154_netdev.h in the kernel.
//Todo: find a better home for these defines.
#define IEEE802154_MAC_SCAN_ED		0
#define IEEE802154_MAC_SCAN_ACTIVE	1
#define IEEE802154_MAC_SCAN_PASSIVE	2
#define IEEE802154_MAC_SCAN_ORPHAN	3

struct ieee802154_beacon_indication {
	uint8_t bsn;
	struct pan_descriptor {
		uint8_t lqi;
	} pan_desc;
	uint8_t sdu_len;
};

struct genl_info;

int cfg802154_inform_beacon( struct ieee802154_beacon_indication *beacon_notify, struct genl_info *info );

#endif /* __NL802154_H */
