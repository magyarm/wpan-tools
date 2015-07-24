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

/**
 * enum nl802154_address_modes - address modes for 802.15.4
 *
 * Found in TABLE 54 of the 2011 802.15.4 spec
 *
 * @NL802154_ADDR_LONG: indicates address is long type
 * @NL802154_ADDR_SHORT: indicates address is short type
 */
enum nl802154_address_modes {
	NL802154_NO_ADDRESS = 0x00,
	NL802154_ADDR_SHORT = 0x02,
	NL802154_ADDR_LONG = 0x03,
};

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

static int print_association_confirm_handler(struct nl_msg *msg, void *arg)
{
	int r;

	uint16_t assoc_short_addr;
	uint8_t status;

	struct genlmsghdr *gnlh;
	struct nlattr *tb[ NL802154_ATTR_MAX + 1 ];
	int i;

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
		tb[ NL802154_ATTR_CONFIRM_STATUS ]
	) ){
		r = -EINVAL;
		goto out;
	}

	assoc_short_addr = nla_get_u16( tb[ NL802154_ATTR_SHORT_ADDR ] );
	status = nla_get_u8( tb[ NL802154_ATTR_CONFIRM_STATUS ] );

	printf(
		"associated short address: %u, "
		"confirm status: %u, ",
		assoc_short_addr,
		status
	);

protocol_error:
	fprintf( stderr, "protocol error\n" );
	r = -EINVAL;

out:
	printf( "returning %d\n", r );
	return r;
}

static int handle_set_association_request(struct nl802154_state *state,
	       struct nl_cb *cb,
	       struct nl_msg *msg,
	       int argc, char **argv,
	       enum id_input id)
{
	int r;

	uint8_t coord_channel;
	uint8_t coord_page;
	enum nl802154_address_modes addr_mode;
	uint16_t coord_pan_id;
	uint64_t coord_addr;
	uint8_t capability_info;

	if ( argc >= 1 ){
		if ( 1 != sscanf( argv[ 0 ], "%u", &coord_channel ) ) {
			goto invalid_arg;
		}
	}
	if ( argc >= 2 ){
		if ( 1 != sscanf( argv[ 1 ], "%u", &coord_page ) ) {
			goto invalid_arg;
		}
	}
	if ( argc >= 3 ){
		if ( 1 != sscanf( argv[ 2 ], "%u", &addr_mode ) ) {
			goto invalid_arg;
		}
	}
	if ( argc >= 4 ){
		if ( 1 != sscanf( argv[ 3 ], "%u", &coord_pan_id ) ) {
			goto invalid_arg;
		}
	}
	if ( argc >= 5 ){
		if ( 1 != sscanf( argv[ 4 ], "%u", &coord_addr ) ) {
			goto invalid_arg;
		}
	}

	if ( argc == 6 ){
		if ( 1 != sscanf( argv[ 5 ], "%u", &capability_info ) ) {
			goto invalid_arg;
		}
	}
	if ( 0 != r ){
		goto out;
	}

	NLA_PUT_U8(msg, NL802154_ATTR_CHANNEL, coord_channel);
	NLA_PUT_U8(msg, NL802154_ATTR_PAGE, coord_page);
	NLA_PUT_U8(msg, NL802154_ATTR_ADDRESS_MODE, addr_mode);
	NLA_PUT_U16(msg, NL802154_ATTR_PAN_ID, htole16(coord_pan_id));
	if ( NL802154_ADDR_SHORT == addr_mode ){
		NLA_PUT_U16(msg, NL802154_ATTR_SHORT_ADDR, htole16(coord_addr));
	} else {
		NLA_PUT_S64(msg, NL802154_ATTR_EXTENDED_ADDR, coord_addr);
	}
	NLA_PUT_U8(msg, NL802154_ATTR_CAPABILITY_INFO, capability_info);

nla_put_failure:
	r = -ENOBUFS;

out:
	return r;
invalid_arg:
	r = 1;
	goto out;
}
COMMAND(set, set_association_request, "<association request>",
	NL802154_CMD_SET_ASSOC_REQ, 0, CIB_NETDEV, handle_set_association_request, NULL);

static int handle_get_association_confirm(struct nl802154_state *state,
	       struct nl_cb *cb,
	       struct nl_msg *msg,
	       int argc, char **argv,
	       enum id_input id)
{
	int r;

	uint16_t assoc_short_addr;
	uint8_t status;

	if ( argc >= 1 ){
		if ( 1 != sscanf( argv[0], "%u", &assoc_short_addr)){
			goto invalid_arg;
		}
	}

	if ( argc == 2 ){
		if ( 1 != sscanf( argv[1], "%u", &status)){
			goto invalid_arg;
		}
	}

	NLA_PUT_U16(msg, NL802154_ATTR_SHORT_ADDR, assoc_short_addr);
	NLA_PUT_U8(msg, NL802154_ATTR_CONFIRM_STATUS, status);

	if ( 0 != r ){
		goto out;
	}

nla_put_failure:
	r = -ENOBUFS;

out:
	return r;
invalid_arg:
	r = 1;
	goto out;
}
COMMAND(get, get_association_request, "<association confirm>",
	NL802154_CMD_GET_ASSOC_CNF, 0, CIB_NETDEV, handle_get_association_confirm, NULL);
