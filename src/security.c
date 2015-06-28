#include <net/if.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

#include "nl_extras.h"
#define CONFIG_IEEE802154_NL802154_EXPERIMENTAL
#include "nl802154.h"
#include "iwpan.h"

static int handle_sec_set(struct nl802154_state *state,
			  struct nl_cb *cb,
			  struct nl_msg *msg,
			  int argc, char **argv,
			  enum id_input id)
{
	unsigned long enabled, key_mode, seclevel, frame_counter,
		      pan_id, short_addr, index, dev_addr_mode;
	unsigned long long extended_addr;
	char *end;

	if (argc < 4)
		return 1;

	/* enabled */
	enabled = strtoul(argv[0], &end, 0);
	if (*end != '\0')
		return 1;

	NLA_PUT_U8(msg, NL802154_ATTR_LLSEC_ENABLED, !!enabled);

	argc--;
	argv++;

	/* key_mode */
	key_mode = strtoul(argv[0], &end, 0);
	if (*end != '\0')
		return 1;

	NLA_PUT_U8(msg, NL802154_ATTR_LLSEC_KEY_MODE, key_mode);

	argc--;
	argv++;

	switch (key_mode) {
	case NL802154_SCF_KEY_IMPLICIT:
		if (argc < 2)
			return 1;

		/* pan_id */
		pan_id = strtoul(argv[0], &end, 0);
		if (*end != '\0')
			return 1;

		NLA_PUT_U16(msg, NL802154_ATTR_PAN_ID, pan_id);

		argc--;
		argv++;

		/* dev_addr_mode */
		dev_addr_mode = strtoul(argv[0], &end, 0);
		if (*end != '\0')
			return 1;

		argc--;
		argv++;

		switch (dev_addr_mode) {
		case NL802154_DEV_ADDR_SHORT:
			if (argc < 1)
				return 1;

			/* dev_addr_short */
			short_addr = strtoul(argv[0], &end, 0);
			if (*end != '\0')
				return 1;

			NLA_PUT_U16(msg, NL802154_ATTR_SHORT_ADDR, short_addr);

			argc--;
			argv++;
			break;
		case NL802154_DEV_ADDR_EXTENDED:
			if (argc < 1)
				return 1;

			/* dev_addr_short */
			extended_addr = strtoul(argv[0], &end, 0);
			if (*end != '\0')
				return 1;

			NLA_PUT_U64(msg, NL802154_ATTR_EXTENDED_ADDR,
				    extended_addr);

			argc--;
			argv++;
			break;
		default:
			return 1;
		}
		break;
	case NL802154_SCF_KEY_INDEX:
		if (argc < 1)
			return 1;

		/* index */
		index = strtoul(argv[0], &end, 0);
		if (*end != '\0')
			return 1;

		NLA_PUT_U8(msg, NL802154_ATTR_LLSEC_KEY_ID, index);

		argc--;
		argv++;
		break;
	case NL802154_SCF_KEY_SHORT_INDEX:
		if (argc < 2)
			return 1;

		/* index */
		index = strtoul(argv[0], &end, 0);
		if (*end != '\0')
			return 1;

		NLA_PUT_U8(msg, NL802154_ATTR_LLSEC_KEY_ID, index);

		argc--;
		argv++;

		/* index */
		short_addr = strtoul(argv[0], &end, 0);
		if (*end != '\0')
			return 1;

		NLA_PUT_U16(msg, NL802154_ATTR_LLSEC_KEY_SOURCE_SHORT,
			    short_addr);

		argc--;
		argv++;
		break;
	case NL802154_SCF_KEY_EXTENDED_INDEX:
		if (argc < 2)
			return 1;

		/* index */
		index = strtoul(argv[0], &end, 0);
		if (*end != '\0')
			return 1;

		NLA_PUT_U8(msg, NL802154_ATTR_LLSEC_KEY_ID, index);

		argc--;
		argv++;

		/* index */
		extended_addr = strtoull(argv[0], &end, 0);
		if (*end != '\0')
			return 1;

		NLA_PUT_U64(msg, NL802154_ATTR_LLSEC_KEY_SOURCE_EXTENDED,
			    extended_addr);

		argc--;
		argv++;
		break;
	default:
		return 1;
	}

	if (argc < 1)
		return 1;

	/* seclevel */
	seclevel = strtoul(argv[0], &end, 0);
	if (*end != '\0')
		return 1;

	NLA_PUT_U8(msg, NL802154_ATTR_LLSEC_SECLEVEL, seclevel);

	argc--;
	argv++;

	/* frame_counter */
	if (argv[0]) {
		frame_counter = strtoul(argv[0], &end, 0);
		if (*end != '\0')
			return 1;

		NLA_PUT_U32(msg, NL802154_ATTR_LLSEC_FRAME_COUNTER, frame_counter);
	}

	return 0;

nla_put_failure:
	return -ENOBUFS;
}
COMMAND(set, secparams, "<enabled> <out_key <key_mode (1 <dev_addr_mode (2 <pan_id> <short_addr>)|(3 <pan_id> <extended_addr>)>|2 <index>|3 <index> <source_short>|4 <index>> <source_extended)>> <seclevel (0|1|2|3|4|5|6|7)> [frame_counter]",
	NL802154_CMD_SET_LLSEC_PARAMS, 0, CIB_NETDEV, handle_sec_set, NULL);

static int handle_sec_get(struct nl802154_state *state,
			  struct nl_cb *cb,
			  struct nl_msg *msg,
			  int argc, char **argv,
			  enum id_input id)
{
	return 0;
}
COMMAND(get, gecparams, NULL,
	NL802154_CMD_SET_LLSEC_PARAMS, 0, CIB_NETDEV, handle_sec_get, NULL);

SECTION(key);

static int print_key_handler(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *tb_msg[NL802154_ATTR_MAX + 1];
	struct nlattr *nl_keys;
	unsigned int *wpan_phy = arg;
	const char *indent = "";
	int rem_keys, ret;

	nla_parse(tb_msg, NL802154_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (wpan_phy && tb_msg[NL802154_ATTR_WPAN_PHY]) {
		unsigned int thiswpan_phy = nla_get_u32(tb_msg[NL802154_ATTR_WPAN_PHY]);
		indent = "\t";
		if (*wpan_phy != thiswpan_phy)
			printf("phy#%d\n", thiswpan_phy);
		*wpan_phy = thiswpan_phy;
	}

	if (tb_msg[NL802154_ATTR_IFNAME])
		printf("%sInterface %s\n", indent, nla_get_string(tb_msg[NL802154_ATTR_IFNAME]));
	else
		printf("%sUnnamed/non-netdev interface\n", indent);

	if (tb_msg[NL802154_ATTR_IFINDEX])
		printf("%s\tifindex %d\n", indent, nla_get_u32(tb_msg[NL802154_ATTR_IFINDEX]));
	if (tb_msg[NL802154_ATTR_WPAN_DEV])
		printf("%s\twpan_dev 0x%llx\n", indent,
		       (unsigned long long)nla_get_u64(tb_msg[NL802154_ATTR_WPAN_DEV]));

	if (tb_msg[NL802154_ATTR_LLSEC_KEY_TABLE]) {
		nla_for_each_nested(nl_keys,
				    tb_msg[NL802154_ATTR_LLSEC_KEY_TABLE],
				    rem_keys) {
			/* TODO introduce new ATTR enum */
			ret = nla_parse_nested(tb_msg, NL802154_ATTR_MAX,
					       nl_keys, NULL);
			if (ret < 0)
				return ret;

			printf("\t-------\n");
			printf("\tkey-id:\n");
			if (tb_msg[NL802154_ATTR_LLSEC_KEY_MODE]) {
				enum nl802154_scf_key_modes mode = nla_get_u8(tb_msg[NL802154_ATTR_LLSEC_KEY_MODE]);
				printf("\t\tmode %d\n", mode);

				if (tb_msg[NL802154_ATTR_LLSEC_KEY_ID])
					printf("\t\tindex 0x%02x\n", nla_get_u8(tb_msg[NL802154_ATTR_LLSEC_KEY_ID]));

				switch (mode) {
				case NL802154_SCF_KEY_IMPLICIT:
					if (tb_msg[NL802154_ATTR_PAN_ID])
						printf("\t\tdevice pan_id 0x%04x\n",
						       nla_get_u16(tb_msg[NL802154_ATTR_PAN_ID]));
					if (tb_msg[NL802154_ATTR_SHORT_ADDR])
						printf("\t\tdevice short_addr 0x%04x\n",
						       nla_get_u16(tb_msg[NL802154_ATTR_SHORT_ADDR]));
					if (tb_msg[NL802154_ATTR_EXTENDED_ADDR])
						printf("\t\tdevice extended_addr 0x%016" PRIx64 "\n",
						       nla_get_u64(tb_msg[NL802154_ATTR_EXTENDED_ADDR]));
					break;
				case NL802154_SCF_KEY_SHORT_INDEX:
					if (tb_msg[NL802154_ATTR_LLSEC_KEY_SOURCE_SHORT])
						printf("\t\tsource_short 0x%08llx\n",
						       nla_get_u32(tb_msg[NL802154_ATTR_LLSEC_KEY_SOURCE_SHORT]));
					break;
				case NL802154_SCF_KEY_EXTENDED_INDEX:
					if (tb_msg[NL802154_ATTR_LLSEC_KEY_SOURCE_EXTENDED])
						printf("\t\tsource_extended 0x%016" PRIx64 "\n",
						       nla_get_u32(tb_msg[NL802154_ATTR_LLSEC_KEY_SOURCE_EXTENDED]));
					break;
				}
			}
		}
	}
}

static int handle_interface_keys(struct nl802154_state *state,
				 struct nl_cb *cb,
				 struct nl_msg *msg,
				 int argc, char **argv,
				 enum id_input id)
{
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, print_key_handler, NULL);
	return 0;
}
COMMAND(key, dump, NULL,
	NL802154_CMD_GET_LLSEC_KEY, 0, CIB_NETDEV, handle_interface_keys,
	"List all stations known, e.g. the AP on managed interfaces");

#if 0
TODO

static int handle_keys_dump(struct nl802154_state *state,
			   struct nl_cb *cb,
			   struct nl_msg *msg,
			   int argc, char **argv,
			   enum id_input id)
{
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, print_keys_handler, NULL);
	return 0;
}
COMMAND(keys, dump, NULL, NL802154_CMD_GET_LLSEC_KEY, NLM_F_DUMP, CIB_NONE, handle_keys_dump,
	 "List all network interfaces for wireless hardware.");
#endif

static int handle_key_add(struct nl802154_state *state,
			  struct nl_cb *cb,
			  struct nl_msg *msg,
			  int argc, char **argv,
			  enum id_input id)
{
	char tmp2[NL802154_LLSEC_KEY_SIZE];
	struct nl_data *tmp;

	tmp2[0] = 0xde;
	tmp2[1] = 0xad;
	tmp2[2] = 0xbe;
	tmp2[3] = 0xef;

	tmp = nl_data_alloc(&tmp2, NL802154_LLSEC_KEY_SIZE);

	NLA_PUT_U8(msg, NL802154_ATTR_LLSEC_KEY_USAGE_FRAME_TYPES, 1 << NL802154_FRAME_DATA);
	NLA_PUT_DATA(msg, NL802154_ATTR_LLSEC_KEY_BYTES, tmp);

	NLA_PUT_U8(msg, NL802154_ATTR_LLSEC_KEY_ID, 23);
	NLA_PUT_U8(msg, NL802154_ATTR_LLSEC_KEY_MODE, NL802154_SCF_KEY_SHORT_INDEX);
	NLA_PUT_U32(msg, NL802154_ATTR_LLSEC_KEY_SOURCE_SHORT, 0xdeadbeef);

	return 0;

nla_put_failure:
	return -ENOBUFS;
}
COMMAND(key, add, "<config_file>", NL802154_CMD_NEW_LLSEC_KEY, 0, CIB_NETDEV,
	handle_key_add, NULL);
