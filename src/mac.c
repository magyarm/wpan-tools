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

enum nl802154_address_modes {
	NL802154_ADDR_NONE,
	NL802154_ADDR_INVAL,
	NL802154_ADDR_SHORT,
	NL802154_ADDR_EXT,
};

struct assoc_req {
	uint32_t channel_number;
	uint32_t channel_page;
	uint32_t coord_pan_id;
	uint8_t coord_addr_mode;
	uint64_t coord_address;
	uint32_t capability_information;
};

static inline bool is_extended_address( uint64_t addr ) {
	static const uint64_t mask = ~((1 << 16) - 1);
	return mask & addr;
}

static inline uint8_t address_mode( uint64_t addr ) {
	return is_extended_address( addr )
		? NL802154_ADDR_EXT
		: NL802154_ADDR_SHORT;
}

static void dump_assoc_req( struct assoc_req *req ) {
	char coord_address[] = "0x0011223344556677";
	if ( is_extended_address( req->coord_address ) ) {
		snprintf( coord_address, sizeof(coord_address),
			"0x%016" PRIx64,
			req->coord_address
		);
	} else {
		snprintf( coord_address, sizeof(coord_address),
			"0x%04x",
			(uint16_t) req->coord_address
		);
	}
	printf(
		"association request:\n\t"
		"channel_number: %u\n\t"
		"channel_page: %u\n\t"
		"coord_pan_id: 0x%04x\n\t"
		"coord_addr_mode: %u\n\t"
		"coord_address: %s\n\t"
		"capability_information: 0x%02x\n",
		req->channel_number,
		req->channel_page,
		req->coord_pan_id,
		req->coord_addr_mode,
		coord_address,
		req->capability_information
	);
}

static int print_assoc_cnf_handler(struct nl_msg *msg, void *arg)
{
	int r;

	uint16_t assoc_short_address;
	uint8_t status;

	struct genlmsghdr *gnlh;
	struct nlattr *tb[ NL802154_ATTR_MAX + 1 ];
	int i,j;

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

	int r;

	int i;
	int argi = 0;

	static struct assoc_req req;

	if (
		! (
			5 == argc &&
			1 == sscanf( argv[ 0 ], "%u", &req.channel_number ) &&
			1 == sscanf( argv[ 1 ], "%u", &req.channel_page ) &&
			(
				(
					0 == strncmp( hex_prefix, argv[ 2 ], strlen( hex_prefix ) ) &&
					1 == sscanf( argv[ 2 ] + strlen( hex_prefix ), "%x", &req.coord_pan_id )
				) ||
				1 == sscanf( argv[ 2 ], "%u", &req.coord_pan_id )
			) &&
			(
				(
					0 == strncmp( hex_prefix, argv[ 3 ], strlen( hex_prefix ) ) &&
					1 == sscanf( argv[ 3 ] + strlen( hex_prefix ), "%"PRIx64, &req.coord_address )
				) ||
				1 == sscanf( argv[ 3 ], "%"PRIu64 , &req.coord_address )
			) &&
			(
				(
					0 == strncmp( hex_prefix, argv[ 4 ], strlen( hex_prefix ) ) &&
					1 == sscanf( argv[ 4 ] + strlen( hex_prefix ), "%x", &req.capability_information )
				) ||
				1 == sscanf( argv[ 4 ], "%u" , &req.capability_information )
			)
		)
	) {
		goto invalid_arg;
	}

	NLA_PUT_U8(msg, NL802154_ATTR_CHANNEL, req.channel_number);
	NLA_PUT_U8(msg, NL802154_ATTR_PAGE, req.channel_page);
	NLA_PUT_U32(msg, NL802154_ATTR_PAN_ID, req.coord_pan_id );

	req.coord_addr_mode = address_mode( req.coord_address );

	NLA_PUT_U8(msg, NL802154_ATTR_ADDR_MODE, req.coord_addr_mode );

	if ( is_extended_address( req.coord_address ) ) {
		NLA_PUT_U64(msg, NL802154_ATTR_EXTENDED_ADDR, req.coord_address );
	} else {
		NLA_PUT_U16(msg, NL802154_ATTR_SHORT_ADDR, req.coord_address );
	}

	NLA_PUT_U8(msg, NL802154_ATTR_ASSOC_CAP_INFO, req.capability_information);

	// dump_assoc_req( &req );

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

COMMAND(set, assoc, "<channel> <page> <coord_panid> <coord_addr> <cap_info>",
	NL802154_CMD_ASSOC_REQ, 0, CIB_PHY, handle_assoc_req, NULL);


struct disassoc_req {
	uint32_t device_addr_mode;
	uint32_t device_panid;
	uint64_t device_address;
	uint32_t disassociate_reason;
	uint32_t tx_indirect;
	uint32_t timeout_ms;
};

static int print_disassoc_cnf_handler(struct nl_msg *msg, void *arg)
{
	int r;

	uint8_t status;
	uint16_t device_addr_mode;
	uint16_t device_panid;
	uint64_t device_address;
	char device_addr_buf[ 32 ];

	struct genlmsghdr *gnlh;
	struct nlattr *tb[ NL802154_ATTR_MAX + 1 ];
	int i,j;

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
		tb[ NL802154_ATTR_DISASSOC_STATUS ] &&
		tb[ NL802154_ATTR_ADDR_MODE ] &&
		tb[ NL802154_ATTR_PAN_ID ] &&
		(
			tb[ NL802154_ATTR_SHORT_ADDR ] ||
			tb[ NL802154_ATTR_EXTENDED_ADDR ]
		)
	) ) {
		fprintf( stderr, "missing some fields\n" );
		r = -EINVAL;
		goto out;
	}

	status = nla_get_u8( tb[ NL802154_ATTR_DISASSOC_STATUS ] );
	device_addr_mode = nla_get_u8( tb[ NL802154_ATTR_ADDR_MODE ] );
	device_panid = nla_get_u16( tb[ NL802154_ATTR_PAN_ID ] );

	switch( device_addr_mode ) {
	case NL802154_ADDR_SHORT:
		if ( tb[ NL802154_ATTR_SHORT_ADDR  ] ) {
			device_address = nla_get_u16( tb[ NL802154_ATTR_SHORT_ADDR ] );
			snprintf( device_addr_buf, sizeof( device_addr_buf ), "0x%04x", (uint16_t)device_address );
			break;
		}
	case NL802154_ADDR_EXT:
		if ( tb[ NL802154_ATTR_EXTENDED_ADDR  ] ) {
			device_address = nla_get_u64( tb[ NL802154_ATTR_EXTENDED_ADDR ] );
			snprintf( device_addr_buf, sizeof( device_addr_buf ), "0x%0" PRIx64, device_address );
			break;
		}
	default:
		fprintf( stderr, "unknown device_addr_mode %d\n", device_addr_mode );
		r = -EINVAL;
		goto out;
	}

	printf(
		"status: %u, "
		"device_pandid: 0x%04x, "
		"device_address: %s\n",
		status,
		device_panid,
		device_addr_buf
	);

	r = 0;
	goto out;

protocol_error:
	fprintf( stderr, "protocol error\n" );
	r = -EINVAL;

out:
	return r;
}

static int handle_disassoc_req(struct nl802154_state *state,
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

	static struct disassoc_req req;

	if (
		! (
			argc >= 3 && argc <= 5 &&
			(
				1 == sscanf( argv[ 0 ], "%u", &req.device_panid ) ||
				(
					!(
						0 == strncmp( hex_prefix, argv[ 0 ], strlen( hex_prefix ) ) &&
						1 == sscanf( argv[ 0 ] + strlen( hex_prefix ), "%x", &req.device_panid )
					)
				)
			) &&
			(
				1 == sscanf( argv[ 1 ], "%"PRId64 , &req.device_address ) ||
				(
					!(
						0 == strncmp( hex_prefix, argv[ 1 ], strlen( hex_prefix ) ) &&
						1 == sscanf( argv[ 1 ] + strlen( hex_prefix ), "%"PRIx64, &req.device_address )
					)
				)
			) &&
			(
				1 == sscanf( argv[ 2 ], "%u" , &req.disassociate_reason ) ||
				(
					!(
						0 == strncmp( hex_prefix, argv[ 2 ], strlen( hex_prefix ) ) &&
						1 == sscanf( argv[ 2 ] + strlen( hex_prefix ), "%x", &req.disassociate_reason )
					)
				)
			)
		)
	) {
		goto invalid_arg;
	}

	if ( argc >= 4 ) {
		if ( 1 != sscanf( argv[ 3 ], "%u" , &req.tx_indirect ) ) {
			goto invalid_arg;
		}
	} else {
		req.tx_indirect = 0;
	}

	if ( 5 == argc ) {
		if ( 1 != sscanf( argv[ 4 ], "%u" , &req.timeout_ms ) ) {
			goto invalid_arg;
		}
	} else {
		req.timeout_ms = 10000;
	}

	req.device_addr_mode =
		is_extended_address( req.device_address )
		? NL802154_ADDR_EXT
		: NL802154_ADDR_SHORT;

	NLA_PUT_U8(msg, NL802154_ATTR_ADDR_MODE, req.device_addr_mode);
	NLA_PUT_U16(msg, NL802154_ATTR_PAN_ID, req.device_panid);

	if ( is_extended_address( req.device_address ) ) {
		NLA_PUT_U64(msg, NL802154_ATTR_EXTENDED_ADDR, req.device_address);
	} else {
		NLA_PUT_U16(msg, NL802154_ATTR_SHORT_ADDR, req.device_address);
	}

	NLA_PUT_U8(msg, NL802154_ATTR_DISASSOC_REASON, req.disassociate_reason);
	NLA_PUT_U8(msg, NL802154_ATTR_DISASSOC_TX_INDIRECT, req.tx_indirect);
	NLA_PUT_U16(msg, NL802154_ATTR_DISASSOC_TIMEOUT_MS, req.timeout_ms);

	r = nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, print_disassoc_cnf_handler, &req );
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

COMMAND(set, disassoc, "<panid> <address> <reason> [<txindirect> [<timeout_ms>]]",
	NL802154_CMD_DISASSOC_REQ, 0, CIB_NETDEV, handle_disassoc_req, NULL);
