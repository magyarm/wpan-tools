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

static int handle_channel_set(struct nl802154_state *state,
			      struct nl_cb *cb,
			      struct nl_msg *msg,
			      int argc, char **argv,
			      enum id_input id)
{
	unsigned long channel;
	unsigned long page;
	char *end;

	if (argc < 2)
		return 1;

	/* PAGE */
	page = strtoul(argv[0], &end, 10);
	if (*end != '\0')
		return 1;

	/* CHANNEL */
	channel = strtoul(argv[1], &end, 10);
	if (*end != '\0')
		return 1;

	NLA_PUT_U8(msg, NL802154_ATTR_PAGE, page);
	NLA_PUT_U8(msg, NL802154_ATTR_CHANNEL, channel);

	return 0;

nla_put_failure:
	return -ENOBUFS;
}
COMMAND(set, channel, "<page> <channel>",
	NL802154_CMD_SET_CHANNEL, 0, CIB_PHY, handle_channel_set, NULL);

static int handle_tx_power_set(struct nl802154_state *state,
			       struct nl_cb *cb,
			       struct nl_msg *msg,
			       int argc, char **argv,
			       enum id_input id)
{
	float dbm;
	char *end;

	if (argc < 1)
		return 1;

	/* TX_POWER */
	dbm = strtof(argv[0], &end);
	if (*end != '\0')
		return 1;

	NLA_PUT_S32(msg, NL802154_ATTR_TX_POWER, DBM_TO_MBM(dbm));

	return 0;

nla_put_failure:
	return -ENOBUFS;
}
COMMAND(set, tx_power, "<dBm>",
	NL802154_CMD_SET_TX_POWER, 0, CIB_PHY, handle_tx_power_set, NULL);

static int handle_cca_mode_set(struct nl802154_state *state,
			       struct nl_cb *cb,
			       struct nl_msg *msg,
			       int argc, char **argv,
			       enum id_input id)
{
	enum nl802154_cca_modes cca_mode;
	char *end;

	if (argc < 1)
		return 1;

	/* CCA_MODE */
	cca_mode = strtoul(argv[0], &end, 10);
	if (*end != '\0')
		return 1;

	if (cca_mode == NL802154_CCA_ENERGY_CARRIER) {
		enum nl802154_cca_opts cca_opt;

		if (argc < 2)
			return 1;

		/* CCA_OPT */
		cca_opt = strtoul(argv[1], &end, 10);
		if (*end != '\0')
			return 1;

		NLA_PUT_U32(msg, NL802154_ATTR_CCA_OPT, cca_opt);
	}

	NLA_PUT_U32(msg, NL802154_ATTR_CCA_MODE, cca_mode);

	return 0;

nla_put_failure:
	return -ENOBUFS;
}
COMMAND(set, cca_mode, "<mode|3 <1|0>>",
	NL802154_CMD_SET_CCA_MODE, 0, CIB_PHY, handle_cca_mode_set, NULL);

static int handle_cca_ed_level(struct nl802154_state *state,
			       struct nl_cb *cb,
			       struct nl_msg *msg,
			       int argc, char **argv,
			       enum id_input id)
{
	float level;
	char *end;

	if (argc < 1)
		return 1;

	/* CCA_ED_LEVEL */
	level = strtof(argv[0], &end);
	if (*end != '\0')
		return 1;

	NLA_PUT_S32(msg, NL802154_ATTR_CCA_ED_LEVEL, DBM_TO_MBM(level));

	return 0;

nla_put_failure:
	return -ENOBUFS;
}
COMMAND(set, cca_ed_level, "<level>",
	NL802154_CMD_SET_CCA_ED_LEVEL, 0, CIB_PHY, handle_cca_ed_level, NULL);

#ifndef IEEE802154_MAX_CHANNEL
#define IEEE802154_MAX_CHANNEL 26
#endif /* IEEE802154_MAX_CHANNEL */
#ifndef IEEE802154_MAX_PAGE
#define IEEE802154_MAX_PAGE 31
#endif /* IEEE802154_MAX_PAGE */

static int parse_nla_array_u8( struct nlattr *a, const int type, uint8_t *value, size_t *len ) {
    int r;

    const size_t maxlen = *len;
    struct nlattr *e;
    size_t _len = 0;
    int rem;

    if ( NULL == a || NULL == value || NULL == len || type <= 0 || type > NL802154_ATTR_MAX ) {
        r = -EINVAL;
        goto out;
    }

    nla_for_each_nested(e, a, rem) {
        if ( _len >= maxlen ) {
            break;
        }
        if ( type != nla_type( e ) ) {
            break;
        }
        value[ _len ] = nla_get_u8( e );
        _len++;
    }

    *len = _len;
    r = 0;
out:
    return r;
}

static int print_ed_scan_handler(struct nl_msg *msg, void *arg)
{
    int r;

    size_t len;
    uint8_t status;
    uint8_t scan_type;
    uint8_t channel_page;
    uint32_t scan_channels = *((uint32_t *)arg);
    uint32_t unscanned_channels;
    uint8_t result_list_size;
    uint8_t ed[ IEEE802154_MAX_CHANNEL + 1 ];
    uint8_t detected_category;

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
        tb[ NL802154_ATTR_SCAN_STATUS ] &&
        tb[ NL802154_ATTR_SCAN_TYPE ] &&
        tb[ NL802154_ATTR_PAGE ] &&
        tb[ NL802154_ATTR_SUPPORTED_CHANNEL ] &&
        tb[ NL802154_ATTR_SCAN_RESULT_LIST_SIZE ] &&
        tb[ NL802154_ATTR_SCAN_ENERGY_DETECT_LIST ] &&
        tb[ NL802154_ATTR_SCAN_DETECTED_CATEGORY ]
    ) ) {
        r = -EINVAL;
        goto out;
    }

    status = nla_get_u8( tb[ NL802154_ATTR_SCAN_STATUS ] );
    scan_type = nla_get_u8( tb[ NL802154_ATTR_SCAN_TYPE ] );
    channel_page = nla_get_u8( tb[ NL802154_ATTR_PAGE ] );
    unscanned_channels = nla_get_u32( tb[ NL802154_ATTR_SUPPORTED_CHANNEL ] );
    result_list_size = nla_get_u32( tb[ NL802154_ATTR_SCAN_RESULT_LIST_SIZE ] );
    len = sizeof( ed ) / sizeof( ed[ 0 ] );
    r = parse_nla_array_u8( tb[ NL802154_ATTR_SCAN_ENERGY_DETECT_LIST ], NL802154_ATTR_SCAN_ENERGY_DETECT_LIST_ENTRY, ed, &len );
    if ( 0 != r ) {
        goto protocol_error;
    }
    detected_category = nla_get_u8( tb[ NL802154_ATTR_SCAN_DETECTED_CATEGORY ] );

    printf(
        "status: %u, "
        "scan_type: %u, "
        "channel_page: %u, "
        "unscanned_channels: %08x, "
        "result_list_size: %u, "
        "energy_detect_list: ",
        status,
        scan_type,
        channel_page,
        unscanned_channels,
        result_list_size
    );
    printf( "{ " );
    for( i=0, j=0; i < sizeof( ed ) / sizeof( ed[ 0 ] ) && j <= result_list_size; i++ ) {
        if ( scan_channels & ( 1 << i ) ) {
            printf( "%u:%u, ", i, ed[ j ]  );
            j++;
        }
    }
    printf( "}, detected_category: %u\n", detected_category );

    r = 0;
    goto out;

protocol_error:
    fprintf( stderr, "protocol error\n" );
    r = -EINVAL;

out:
    return r;
}

static int handle_ed_scan(struct nl802154_state *state,
               struct nl_cb *cb,
               struct nl_msg *msg,
               int argc, char **argv,
               enum id_input id)
{
    int r;

    int i;

    const uint8_t scan_type = 0; // XXX: define IEEE802154_MAC_SCAN_ED (FIXME: don't use magic numbers)
    uint32_t channel_page = 0;
    static uint32_t scan_channels;
    uint32_t scan_duration = 3;

    if ( argc >= 1 ) {
        if ( 1 != sscanf( argv[ 0 ], "%u", &channel_page ) ) {
            goto invalid_arg;
        }
    }
    // specify a sane default of scan_channels
    // if channel_page was specified or not
    switch( channel_page ) {
    case 0:
        scan_channels = 0x7fff800;
        /* no break */
    default:
        break;
    }
    if ( argc >= 2 ) {
        if ( ! (
            ( 0 == strncmp( "0x", argv[ 1], 2 ) && 1 == sscanf( argv[ 1 ] + 2, "%x", &scan_channels ) ) ||
            1 == sscanf( argv[ 1 ], "%u", &scan_channels )
        ) ) {
            goto invalid_arg;
        }
    }
    if ( argc == 3 ) {
        if ( 1 != sscanf( argv[ 2 ], "%u", &scan_duration ) ) {
            goto invalid_arg;
        }
    }
    if ( argc > 3 ) {
        goto invalid_arg;
    }

    NLA_PUT_U8(msg, NL802154_ATTR_SCAN_TYPE, scan_type);
    NLA_PUT_U32(msg, NL802154_ATTR_SUPPORTED_CHANNEL, scan_channels );
    NLA_PUT_U8(msg, NL802154_ATTR_SCAN_DURATION, scan_duration);
    NLA_PUT_U8(msg, NL802154_ATTR_PAGE, channel_page);

    r = nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, print_ed_scan_handler, &scan_channels );
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

COMMAND(get, ed_scan, "[<page> [<channels> [<duration>]]]",
    NL802154_CMD_ED_SCAN_REQ, 0, CIB_PHY, handle_ed_scan, NULL);

static int print_beacon_notify_indication(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh;
	struct nlattr *tb_msg[NL802154_ATTR_MAX + 1];
	unsigned int *wpan_phy = arg;
	int r;

	gnlh = nlmsg_data( nlmsg_hdr( msg ) );
	if ( NULL ==  gnlh ) {
	    fprintf( stderr, "gnlh was null\n" );
	    goto protocol_error;
	}

	r = nla_parse( tb_msg, NL802154_ATTR_MAX, genlmsg_attrdata( gnlh, 0 ),
	      genlmsg_attrlen( gnlh, 0 ), NULL );
	if ( 0 != r ) {
	    fprintf( stderr, "nla_parse\n" );
	    goto protocol_error;
	}

        printf("beacon_indication:\n");
	if (tb_msg[NL802154_ATTR_BEACON_SEQUENCE_NUMBER]) {
		printf("\tBSN: %d\n", nla_get_u32(tb_msg[NL802154_ATTR_BEACON_SEQUENCE_NUMBER]));
	}

	goto out;

protocol_error:
    fprintf( stderr, "protocol error\n" );
    r = -EINVAL;
out:
    return NL_SKIP;
}

static int handle_beacon_notify(struct nl802154_state *state,
				 struct nl_cb *cb,
				 struct nl_msg *msg,
				 int argc, char **argv,
				 enum id_input id)
{
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, print_beacon_notify_indication, NULL);
	return 0;
}

COMMAND(set, beacon_notify, "<none>",
		NL802154_CMD_BEACON_NOTIFY_IND, 0, CIB_PHY, handle_beacon_notify, NULL);

static int print_active_scan_results( struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh;
	struct nlattr *tb_msg[NL802154_ATTR_MAX + 1];
	unsigned int *wpan_phy = arg;
	int r;

	gnlh = nlmsg_data( nlmsg_hdr( msg ) );
	if ( NULL ==  gnlh ) {
	    fprintf( stderr, "gnlh was null\n" );
	    goto protocol_error;
	}

	r = nla_parse( tb_msg, NL802154_ATTR_MAX, genlmsg_attrdata( gnlh, 0 ),
	      genlmsg_attrlen( gnlh, 0 ), NULL );
	if ( 0 != r ) {
	    fprintf( stderr, "nla_parse\n" );
	    goto protocol_error;
	}

	printf("Active Scan print results: \n");
	//Check if the message is a beacon or the last status message
	if (tb_msg[NL802154_ATTR_PAN_DESCRIPTOR]) {
		struct nlattr *tb_pan_desc[NL802154_ATTR_MAX + 1];

		static struct nla_policy pan_desc_policy[NL802154_ATTR_MAX + 1] = {
			[NL802154_ATTR_PAN_DESC_SRC_ADDR_MODE] = { .type = NLA_U8 },
			[NL802154_ATTR_PAN_DESC_SRC_PAN_ID] = { .type = NLA_U16 },
			[NL802154_ATTR_PAN_DESC_SRC_ADDR] = { .type = NLA_U32 },
			[NL802154_ATTR_PAN_DESC_CHANNEL_NUM] = { .type = NLA_U8 },
			[NL802154_ATTR_PAN_DESC_CHANNEL_PAGE] = { .type = NLA_U8 },
			[NL802154_ATTR_PAN_DESC_SUPERFRAME_SPEC] = { .type = NLA_U8 },
			[NL802154_ATTR_PAN_DESC_GTS_PERMIT] = { .type = NLA_U32 },
			[NL802154_ATTR_PAN_DESC_LQI] = { .type = NLA_U8 },
			[NL802154_ATTR_PAN_DESC_TIME_STAMP] = { .type = NLA_U32 },
			[NL802154_ATTR_PAN_DESC_SEC_STATUS] = { .type = NLA_U8 },
			[NL802154_ATTR_PAN_DESC_SEC_LEVEL] = { .type = NLA_U8 },
			[NL802154_ATTR_PAN_DESC_KEY_ID_MODE] = { .type = NLA_U8 },
			[NL802154_ATTR_PAN_DESC_KEY_SRC] = { .type = NLA_U8 },
			[NL802154_ATTR_PAN_DESC_KEY_INDEX] = { .type = NLA_U8 },
		};

		printf("PAN descriptor:\n");

		r = nla_parse_nested(tb_pan_desc, NL802154_ATTR_MAX,
				       tb_msg[NL802154_ATTR_PAN_DESCRIPTOR],
				       pan_desc_policy);
		if ( 0 != r ) {
		    fprintf( stderr, "nla_parse_nested\n" );
		    goto protocol_error;
		}

		if (tb_pan_desc[NL802154_ATTR_PAN_DESC_SRC_ADDR_MODE]) {
		    printf("\tSrc Addr Mode: %d\n", nla_get_u8(tb_pan_desc[NL802154_ATTR_PAN_DESC_SRC_ADDR_MODE]));
		}
		if (tb_pan_desc[NL802154_ATTR_PAN_DESC_SRC_PAN_ID]) {
		    printf("\tSrc PAN Id   : %x\n", nla_get_u16(tb_pan_desc[NL802154_ATTR_PAN_DESC_SRC_PAN_ID]));
		}
		if (tb_pan_desc[NL802154_ATTR_PAN_DESC_SRC_ADDR]) {
		    printf("\tSrc Addr     : %d\n", nla_get_u32(tb_pan_desc[NL802154_ATTR_PAN_DESC_SRC_ADDR]));
		}
		if (tb_pan_desc[NL802154_ATTR_PAN_DESC_CHANNEL_NUM]) {
		    printf("\tChannel Num  : %d\n", nla_get_u8(tb_pan_desc[NL802154_ATTR_PAN_DESC_CHANNEL_NUM]));
		}
		if (tb_pan_desc[NL802154_ATTR_PAN_DESC_CHANNEL_PAGE]) {
		    printf("\tChannel Page : %d\n", nla_get_u8(tb_pan_desc[NL802154_ATTR_PAN_DESC_CHANNEL_PAGE]));
		}
		if (tb_pan_desc[NL802154_ATTR_PAN_DESC_SUPERFRAME_SPEC]) {
		    printf("\tSF spec      : %x\n", nla_get_u8(tb_pan_desc[NL802154_ATTR_PAN_DESC_SUPERFRAME_SPEC]));
		}
		if (tb_pan_desc[NL802154_ATTR_PAN_DESC_GTS_PERMIT]) {
			char *gts = nla_get_u32(tb_pan_desc[NL802154_ATTR_PAN_DESC_GTS_PERMIT]) ? "TRUE" : "FALSE";
		    printf("\tGTS permit   : %s\n", gts);
		}
		if (tb_pan_desc[NL802154_ATTR_PAN_DESC_LQI]) {
		    printf("\tLQI          : %x\n", nla_get_u8(tb_pan_desc[NL802154_ATTR_PAN_DESC_LQI]));
		}
		if (tb_pan_desc[NL802154_ATTR_PAN_DESC_TIME_STAMP]) {
		    printf("\tTimestamp    : %x\n", nla_get_u32(tb_pan_desc[NL802154_ATTR_PAN_DESC_TIME_STAMP]));
		}
		if (tb_pan_desc[NL802154_ATTR_PAN_DESC_SEC_STATUS]) {
		    printf("\tSec status   : %x\n", nla_get_u8(tb_pan_desc[NL802154_ATTR_PAN_DESC_SEC_STATUS]));
		}
		if (tb_pan_desc[NL802154_ATTR_PAN_DESC_SEC_LEVEL]) {
		    printf("\tSec level    : %x\n", nla_get_u8(tb_pan_desc[NL802154_ATTR_PAN_DESC_SEC_LEVEL]));
		}
		if (tb_pan_desc[NL802154_ATTR_PAN_DESC_KEY_ID_MODE]) {
		    printf("\tKey Id Mode  : %x\n", nla_get_u8(tb_pan_desc[NL802154_ATTR_PAN_DESC_KEY_ID_MODE]));
		}
		if (tb_pan_desc[NL802154_ATTR_PAN_DESC_KEY_SRC]) {
		    printf("\tKey Src      : %x\n", nla_get_u8(tb_pan_desc[NL802154_ATTR_PAN_DESC_KEY_SRC]));
		}
		if (tb_pan_desc[NL802154_ATTR_PAN_DESC_KEY_INDEX]) {
		    printf("\tKey Index    : %d\n", nla_get_u8(tb_pan_desc[NL802154_ATTR_PAN_DESC_KEY_INDEX]));
		}
		goto out;

	} else if( tb_msg[NL802154_ATTR_SCAN_STATUS]){
		printf( "Active Scan Confirm \n");
		printf( "\tScan Status: %d\n",nla_get_u8( tb_msg[NL802154_ATTR_SCAN_STATUS] ) );
		printf( "\tScan Type: %d\n",nla_get_u8( tb_msg[NL802154_ATTR_SCAN_TYPE] ) );
		printf( "\tAttribute Page: %d\n",nla_get_u8( tb_msg[NL802154_ATTR_PAGE] ) );
		printf( "\tScan Detect Category: %d\n",nla_get_u8( tb_msg[NL802154_ATTR_SCAN_DETECTED_CATEGORY] ) );
		printf( "\tScan Result List Size: %d\n",nla_get_u8( tb_msg[NL802154_ATTR_SCAN_RESULT_LIST_SIZE] ) );

	} else {
		goto protocol_error;
	}

protocol_error:
	fprintf( stderr, "protocol error\n" );
	r = -EINVAL;
out:
	return NL_SKIP;
}

static int handle_active_scan(struct nl802154_state *state,
               struct nl_cb *cb,
               struct nl_msg *msg,
               int argc, char **argv,
               enum id_input id)
{
	int r;
	int i;

	const uint8_t scan_type = IEEE802154_MAC_SCAN_ACTIVE;
	uint32_t channel_page = 0;
	static uint32_t scan_channels;
	uint32_t scan_duration;

	if ( argc >= 1 ) {
		if ( 1 != sscanf( argv[ 0 ], "%u", &channel_page ) ) {
			goto invalid_arg;
		}
	}
	if ( argc >= 2 ) {
		if ( ! (
				( 0 == strncmp( "0x", argv[ 1], 2 ) && 1 == sscanf( argv[ 1 ] + 2, "%x", &scan_channels ) ) ||
				1 == sscanf( argv[ 1 ], "%u", &scan_channels )
		) ) {
			goto invalid_arg;
		}
	}
	if ( argc == 3 ) {
		if ( 1 != sscanf( argv[ 2 ], "%u", &scan_duration ) ) {
			goto invalid_arg;
		}
	}
	if ( argc > 3 ) {
		goto invalid_arg;
	}

	NLA_PUT_U8(msg, NL802154_ATTR_SCAN_TYPE, scan_type);
	NLA_PUT_U32(msg, NL802154_ATTR_SUPPORTED_CHANNEL, scan_channels );
	NLA_PUT_U8(msg, NL802154_ATTR_SCAN_DURATION, scan_duration);
	NLA_PUT_U8(msg, NL802154_ATTR_PAGE, channel_page);

	r = nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, print_active_scan_results, &scan_channels );
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
COMMAND(set, active_scan, "<channel_page> <scan channel bitmask> <scan duration>",
		NL802154_CMD_ACTIVE_SCAN_REQ, 0, CIB_NETDEV, handle_active_scan, NULL);
