#include <net/if.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>

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

struct assoc_req {
	uint32_t channel_number;
	uint32_t channel_page;
	uint16_t coord_pan_id;
	uint64_t coord_address;
	uint32_t capability_information;
	uint16_t timeout_ms;
};

static inline bool is_extended_address( uint64_t addr ) {
	static const uint64_t mask = ~((1 << 16) - 1);
	return mask & addr;
}

static int print_assoc_cnf_handler(struct nl_msg *msg, void *arg)
{
	int r;

	uint16_t assoc_short_address;
	uint8_t status;
	struct genlmsghdr *gnlh;
	struct nlattr *tb[ NL802154_ATTR_MAX + 1 ];

	gnlh = nlmsg_data( nlmsg_hdr( msg ) );
	if ( NULL ==  gnlh ) {
		fprintf( stderr, "gnlh was null\n" );
		goto protocol_error;
	}

	r = nla_parse( tb, NL802154_ATTR_MAX, genlmsg_attrdata( gnlh, 0 ),
		  genlmsg_attrlen( gnlh, 0 ), NULL );
	if ( 0 != r ) {
		fprintf( stderr, "nla_parse\n" );
		goto protocol_error;
	}

	if ( ! (
		tb[ NL802154_ATTR_SHORT_ADDR ] &&
		tb[ NL802154_ATTR_ASSOC_STATUS ]
	) ) {
		r = -EINVAL;
		goto out;
	}

	assoc_short_address = nla_get_u16( tb[ NL802154_ATTR_SHORT_ADDR ] );
	status = nla_get_u8( tb[ NL802154_ATTR_ASSOC_STATUS ] );

	printf(
		"Association Confirm: "
		"short_address: 0x%04x, "
		"status: %u\n",
		assoc_short_address,
		status
	);

	r = 0;
	goto out;

protocol_error:
	fprintf( stderr, "protocol error\n" );
	r = -EINVAL;

out:
	return r;
}

static int handle_assoc_req(struct nl802154_state *state,
		struct nl_cb *cb,
		struct nl_msg *msg,
		int argc,
		char **argv,
		enum id_input id)
{
	static const char *hex_prefix = "0x";
	enum nl802154_address_modes {
		NL802154_ADDR_NONE,
		NL802154_ADDR_INVAL,
		NL802154_ADDR_SHORT,
		NL802154_ADDR_EXT,
	};

	int r;

	int i;

	static struct assoc_req req;

	if (
		! (
			6 == argc &&
			1 == sscanf( argv[ 0 ], "%u", &req.channel_number ) &&
			1 == sscanf( argv[ 1 ], "%u", &req.channel_page ) &&
			(
				1 == sscanf( argv[ 2 ], "%u", &req.coord_pan_id ) ||
				(
					!(
						0 == strncmp( hex_prefix, argv[ 2 ], strlen( hex_prefix ) ) &&
						1 == sscanf( argv[ 2 ] + strlen( hex_prefix ), "%x", &req.coord_pan_id )
					)
				)
			) &&
			(
				1 == sscanf( argv[ 3 ], "%"PRId64 , &req.coord_address ) ||
				(
					!(
						0 == strncmp( hex_prefix, argv[ 3 ], strlen( hex_prefix ) ) &&
						1 == sscanf( argv[ 3 ] + strlen( hex_prefix ), "%"PRIx64, &req.coord_address )
					)
				)
			) &&
			(
				1 == sscanf( argv[ 4 ], "%u" , &req.capability_information ) ||
				(
					!(
						0 == strncmp( hex_prefix, argv[ 4 ], strlen( hex_prefix ) ) &&
						1 == sscanf( argv[ 4 ] + strlen( hex_prefix ), "%x", &req.capability_information )
					)
				)
			) && 1 == sscanf( argv[ 5 ], "%u", &req.timeout_ms )
		)
	) {
		goto invalid_arg;
	}

	NLA_PUT_U8(msg, NL802154_ATTR_CHANNEL, req.channel_number);
	NLA_PUT_U8(msg, NL802154_ATTR_PAGE, req.channel_page);
	NLA_PUT_U16(msg, NL802154_ATTR_PAN_ID, req.coord_pan_id );

	if ( is_extended_address( req.coord_address ) ) {
		NLA_PUT_U8(msg, NL802154_ATTR_ADDR_MODE, NL802154_ADDR_EXT );
		NLA_PUT_U64(msg, NL802154_ATTR_EXTENDED_ADDR, req.coord_address );
	} else {
		NLA_PUT_U8(msg, NL802154_ATTR_ADDR_MODE, NL802154_ADDR_SHORT );
		NLA_PUT_U16(msg, NL802154_ATTR_SHORT_ADDR, req.coord_address );
	}

	NLA_PUT_U8(msg, NL802154_ATTR_ASSOC_CAP_INFO, req.capability_information);

	NLA_PUT_U16(msg, NL802154_ATTR_ASSOC_TIMEOUT_MS, req.timeout_ms);

	r = nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, print_assoc_cnf_handler, &req );
	if ( 0 != r ) {
		goto out;
	}

	r = 0;
	goto out;

nla_put_failure:
	r = -ENOBUFS;
out:
	return r;
invalid_arg:
	r = 1;
	goto out;
}

COMMAND(set, assoc, "<channel> <page> <coord_panid> <coord_addr> <cap_info> <timeout_ms>",
	NL802154_CMD_ASSOC_REQ, 0, CIB_PHY, handle_assoc_req, NULL);
