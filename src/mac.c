#include <net/if.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

#include "nl_extras.h"
#include "nl802154.h"
#include "iwpan.h"

static int handle_pan_id_set(struct nl802154_state *state,
			     struct nl_cb *cb,
			     struct nl_msg *msg,
			     int argc, char **argv,
			     enum id_input id)
{
	unsigned long pan_id;
	char *end;

	if (argc < 1)
		return 1;

	/* PAN ID */
	pan_id = strtoul(argv[0], &end, 0);
	if (*end != '\0')
		return 1;

	NLA_PUT_U16(msg, NL802154_ATTR_PAN_ID, htole16(pan_id));

	return 0;

nla_put_failure:
	return -ENOBUFS;
}
COMMAND(set, pan_id, "<pan_id>",
	NL802154_CMD_SET_PAN_ID, 0, CIB_NETDEV, handle_pan_id_set, NULL);

static int handle_short_addr_set(struct nl802154_state *state,
				 struct nl_cb *cb,
				 struct nl_msg *msg,
				 int argc, char **argv,
				 enum id_input id)
{
	unsigned long short_addr;
	char *end;

	if (argc < 1)
		return 1;

	/* SHORT ADDR */
	short_addr = strtoul(argv[0], &end, 0);
	if (*end != '\0')
		return 1;

	NLA_PUT_U16(msg, NL802154_ATTR_SHORT_ADDR, htole16(short_addr));

	return 0;

nla_put_failure:
	return -ENOBUFS;
}
COMMAND(set, short_addr, "<short_addr>",
	NL802154_CMD_SET_SHORT_ADDR, 0, CIB_NETDEV, handle_short_addr_set, NULL);

static int handle_max_frame_retries_set(struct nl802154_state *state,
					struct nl_cb *cb,
					struct nl_msg *msg,
					int argc, char **argv,
					enum id_input id)
{
	long retries;
	char *end;

	if (argc < 1)
		return 1;

	/* RETRIES */
	retries = strtol(argv[0], &end, 0);
	if (*end != '\0')
		return 1;

	NLA_PUT_S8(msg, NL802154_ATTR_MAX_FRAME_RETRIES, retries);

	return 0;

nla_put_failure:
	return -ENOBUFS;
}
COMMAND(set, max_frame_retries, "<retries>",
	NL802154_CMD_SET_MAX_FRAME_RETRIES, 0, CIB_NETDEV,
	handle_max_frame_retries_set, NULL);

static int handle_backoff_exponent(struct nl802154_state *state,
				   struct nl_cb *cb,
				   struct nl_msg *msg,
				   int argc, char **argv,
				   enum id_input id)
{
	unsigned long max_be;
	unsigned long min_be;
	char *end;

	if (argc < 2)
		return 1;

	/* MIN_BE */
	min_be = strtoul(argv[0], &end, 0);
	if (*end != '\0')
		return 1;

	/* MAX_BE */
	max_be = strtoul(argv[1], &end, 0);
	if (*end != '\0')
		return 1;

	NLA_PUT_U8(msg, NL802154_ATTR_MIN_BE, min_be);
	NLA_PUT_U8(msg, NL802154_ATTR_MAX_BE, max_be);

	return 0;

nla_put_failure:
	return -ENOBUFS;
}
COMMAND(set, backoff_exponents, "<min_be> <max_be>",
	NL802154_CMD_SET_BACKOFF_EXPONENT, 0, CIB_NETDEV,
	handle_backoff_exponent, NULL);

static int handle_max_csma_backoffs(struct nl802154_state *state,
				    struct nl_cb *cb,
				    struct nl_msg *msg,
				    int argc, char **argv,
				    enum id_input id)
{
	unsigned long backoffs;
	char *end;

	if (argc < 1)
		return 1;

	/* BACKOFFS */
	backoffs = strtoul(argv[0], &end, 0);
	if (*end != '\0')
		return 1;

	NLA_PUT_U8(msg, NL802154_ATTR_MAX_CSMA_BACKOFFS, backoffs);

	return 0;

nla_put_failure:
	return -ENOBUFS;
}
COMMAND(set, max_csma_backoffs, "<backoffs>",
	NL802154_CMD_SET_MAX_CSMA_BACKOFFS, 0, CIB_NETDEV,
	handle_max_csma_backoffs, NULL);


static int handle_lbt_mode(struct nl802154_state *state,
			   struct nl_cb *cb,
			   struct nl_msg *msg,
			   int argc, char **argv,
			   enum id_input id)
{
	unsigned long mode;
	char *end;

	if (argc < 1)
		return 1;

	/* LBT_MODE */
	mode = strtoul(argv[0], &end, 0);
	if (*end != '\0')
		return 1;

	NLA_PUT_U8(msg, NL802154_ATTR_LBT_MODE, mode);

	return 0;

nla_put_failure:
	return -ENOBUFS;
}
COMMAND(set, lbt, "<1|0>",
	NL802154_CMD_SET_LBT_MODE, 0, CIB_NETDEV, handle_lbt_mode, NULL);

static int handle_set_association_request(struct nl802154_state *state,
	       struct nl_cb *cb,
	       struct nl_msg *msg,
	       int argc, char **argv,
	       enum id_input id)
{
	unsigned long channel;
	unsigned long page;
	enum nl802154_address_modes addr_mode;
	unsigned long pan_id;
	unsigned long short_addr;
	unsigned long long extended_addr;
	unsigned short capability_info;

	// Do the same security information like GET ED SCAN
	unsigned long security_level = 0;
	unsigned long key_id_mode = 0;
	char key_source[4 + 1];
	unsigned long key_index = 0;

	char *end;

	memset( key_source, 0xff, 4 );
	key_source[ 4 ] = '\0';

	if (argc < 6)
		return 1;

	/* CHANNEL */
	channel = strtoul(argv[0], &end, 10);
		if (*end != '\0')
			return 1;

	/* PAGE */
	page = strtoul(argv[1], &end, 10);
		if (*end != '\0')
			return 1;

	/* ADDR MODE */
	addr_mode = strtoul(argv[2], &end, 10);
		if (*end != '\0')
			return 1;

	/* PAN ID */
	pan_id = strtoul(argv[3], &end, 0);
	if (*end != '\0')
		return 1;

	/* SHORT ADDR */
	if ( NL802154_ADDR_SHORT == addr_mode ){
		short_addr = strtoul(argv[4], &end, 0);
		if (*end != '\0')
			return 1;
	}
	/* LONG ADDR */
	else {
		extended_addr = strtoull(argv[4], &end, 0);
		if (*end != '\0')
			return 1;
	}

	/* CAPABILITY INFO */
	capability_info = strtoul(argv[5], &end, 0);
	if (*end != '\0')
		return 1;

	NLA_PUT_U8(msg, NL802154_ATTR_CHANNEL, channel);
	NLA_PUT_U8(msg, NL802154_ATTR_PAGE, page);
	NLA_PUT_U8(msg, NL802154_ATTR_ADDRESS_MODE, addr_mode);
	NLA_PUT_U16(msg, NL802154_ATTR_PAN_ID, htole16(pan_id));
	if ( NL802154_ADDR_SHORT == addr_mode ){
		NLA_PUT_U16(msg, NL802154_ATTR_SHORT_ADDR, htole16(short_addr));
	} else {
		NLA_PUT_S64(msg, NL802154_ATTR_EXTENDED_ADDR, extended_addr);
	}
	NLA_PUT_U8(msg, NL802154_ATTR_CAPABILITY_INFO, capability_info);
	NLA_PUT_U8(msg, NL802154_ATTR_SECURITY_LEVEL, security_level);
	NLA_PUT_U8(msg, NL802154_ATTR_KEY_ID_MODE, key_id_mode);
	NLA_PUT_STRING(msg, NL802154_ATTR_KEY_SOURCE, key_source);
	NLA_PUT_U8(msg, NL802154_ATTR_KEY_INDEX, key_index);

	nla_put_failure:
		return -ENOBUFS;
}
COMMAND(set, set_association_request, "<association request>",
	NL802154_CMD_SET_ASSOC_REQUEST, 0, CIB_NETDEV, handle_set_association_request, NULL);

static int handle_get_association_confirm(struct nl802154_state *state,
	       struct nl_cb *cb,
	       struct nl_msg *msg,
	       int argc, char **argv,
	       enum id_input id)
{
	unsigned long assoc_short_addr;
	unsigned long status;

	// Do the same security information like GET ED SCAN
	unsigned long security_level = 0;
	unsigned long key_id_mode = 0;
	char key_source[4 + 1];
	unsigned long key_index = 0;

	char *end;

	if (argc < 2)
		return 1;

	/* ASSOCIATED SHORT ADDRESS */
	assoc_short_addr = strtol(argv[0], &end, 0);
	if (*end != '\0')
		return 1;

	/* CONFIRM STATUS */
	status = strtol(argv[1], &end, 0);
	if (*end != '\0')
		return 1;

	NLA_PUT_U16(msg, NL802154_ATTR_SHORT_ADDR, assoc_short_addr);
	NLA_PUT_U8(msg, NL802154_ATTR_CONFIRM_STATUS, status);
	NLA_PUT_U8(msg, NL802154_ATTR_SECURITY_LEVEL, security_level);
	NLA_PUT_U8(msg, NL802154_ATTR_KEY_ID_MODE, key_id_mode);
	NLA_PUT_STRING(msg, NL802154_ATTR_KEY_SOURCE, key_source);
	NLA_PUT_U8(msg, NL802154_ATTR_KEY_INDEX, key_index);

	nla_put_failure:
		return -ENOBUFS;
}
COMMAND(get, get_association_request, "<association confirm>",
	NL802154_CMD_GET_ASSOC_CONFIRM, 0, CIB_NETDEV, handle_get_association_confirm, NULL);
