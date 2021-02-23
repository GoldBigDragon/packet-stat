// 과제를 하기 위해 우연히 필자의 깃허브로
// 흘러 들어온 BoB 멘티들을 위해 모든 주석을 남깁니다.

/*
    과제 내용
    - pcap file로부터 packet을 읽어서 IP별 송신 패킷 갯수, 수신 패킷 갯수, 송신 패킷 바이트, 수신 패킷 바이트를 출력하는 프로그램을 작성하라.
    ① ipv4(uint32_t)를 key로 하여 검색하는 방법 이해.
    ② user defined class를 key로 하여 검색하는 방법 이해.
    ③ composite key로 검색하는 방법 이해.
    ④ conversation보다 flow로 처리하는 것이 더 효율적이다라는 것을 이해.
*/

// 패킷 관련 핸들링을 위해 pcap 라이브러리를 추가합니다.
#include <pcap.h>
// printf를 사용하여 화면 출력을 하기 위해 Standard Input/Output 관련 라이브러리를 추가합니다.
#include <stdio.h>
// 패킷 헤더 구조체 모음집을 컴파일 시, 현재 디렉터리 내 파일로 불러옵니다.
#include "libnet-headers.h"
// MAP 구조 사용을 위해 map 라이브러리를 추가합니다.
#include <map>

// 통신 내역을 담은 구조체입니다.
struct Transmission {
    // 보낸 패킷 수
    int sendPacket;
    // 보낸 패킷 총 Bytes
    int sendBytes;
    // 받은 패킷 수
    int recivedPacket;
    // 받은 패킷 총 Bytes
    int recivedBytes;
};

// 정수를 Key값으로하여 통신내역 구조체를 Value로 삼는 MAP 타입을 선언합니다.
typedef std::map<std::uint32_t, Transmission> AddressMap;
// 선언된 타입을 이용하여 통신 내역을 담을 MAP 변수를 생성합니다.
AddressMap transmissionMap;
    
// 명령을 잘못 입력 했을 때 아래 함수를 통해 사용법을 알려줍니다.
void usage() {
    // 프로그램 사용 시, packet-stat <파일 명> 을 입력하도록 합니다.
    printf("syntax: packet-stat <pcap file name>\n");
    // 예시를 들어줍니다.
    printf("sample: packet-stat test.pcap\n");
}

// MAP에 IP 주소(정수형)를 Key값으로 하여 통신 내역을 저장합니다.
void appendMap(uint32_t ip, int length, bool isSend) {
    // MAP 구조체의 연속적인 구조를 불러옵니다.
    AddressMap::iterator iter;
    // 입력받은 IP주소에 해당하는 KEY값이 있는지 확인합니다.
    iter = transmissionMap.find(ip);
    // 입력받은 IP 주소에 해당하는 KEY값이 없다면
    if (iter == transmissionMap.end()) {
        // MAP에 새로운 통신내역을 추가합니다.
        iter = transmissionMap.insert(std::make_pair(ip, Transmission())).first;
    }
    // 발신자 정보일 경우, 발신 패킷 수와 Bytes를 더합니다.
    if (isSend) {
        iter->second.sendPacket++;
        iter->second.sendBytes += length;
    // 수신자 정보일 경우, 수신 패킷 수와 Bytes를 더합니다.
    } else {
        iter->second.recivedPacket++;
        iter->second.recivedBytes += length;
    }
}

// 프로그램의 시작 함수입니다.
int main(int argc, char* argv[]) {
    // 만일, 파라미터를 하나도 입력하지 않거나, 1개보다 많이 입력 하였을 경우
    if (argc != 2) {
        // 사용법을 출력합니다.
        usage();
        // 프로그램을 강제 종료시킵니다.
        exit(1);
    }
    // 입력받은 파일 명을 담습니다.
    char* fileName = argv[1];
    // 에러 정보를 담을 버퍼를 준비합니다.
    char errbuf[PCAP_ERRBUF_SIZE];
    // pcap 파일을 오프라인으로 엽니다.
    pcap_t *handle = pcap_open_offline(fileName, errbuf);
    // pcap 파일이 없거나 올바르지 않을 경우, 에러를 출력하고 종료시킵니다.
    if (!handle) {
        printf("%s\n", errbuf);
        exit(1);
    }
    // 패킷 헤더 구조체를 미리 선언합니다.
    struct pcap_pkthdr *header;
    // libnet에서 미리 지정한 IP 헤더 구조체를 이용하여 손쉽게 IP 헤더를 담을 변수를 생성합니다.
    struct libnet_ipv4_hdr* ipHeader;
    // 패킷 내용을 담을 변수를 생성합니다.
    const u_char *packet;
    // 파일 내 모든 패킷을 하나 씩 꺼내 봅니다.
    while (int returnValue = pcap_next_ex(handle, &header, &packet) >= 0) {
        // 패킷을 IP헤더에 맞추어 봅니다.
        ipHeader = (struct libnet_ipv4_hdr*) (packet + sizeof(struct libnet_ethernet_hdr));
        // IP헤더에서 발신자 IP 주소를 추출하고, 패킷 헤더에서 패킷 총 길이를 추출하여 발신자로써 통신내역MAP에 등록합니다.
        appendMap(ipHeader->ip_src.s_addr, header->len, true);
        // IP헤더에서 수신자 IP 주소를 추출하고, 패킷 헤더에서 패킷 총 길이를 추출하여 수신자로써 통신내역MAP에 등록합니다.
        appendMap(ipHeader->ip_dst.s_addr, header->len, false);
    }
    
    // 통신내역MAP에 저장된 모든 KEY값을 차례대로 열람합니다.
    for(auto iter = transmissionMap.begin(); iter != transmissionMap.end(); iter++) {
        // 통신내역MAP의 KEY값을 꺼내어 IP주소에 담습니다.
        in_addr ip = {iter->first};
        // 통신내역MAP의 VALUE값을 꺼내어 Transmission에 담습니다.
        Transmission transmission = iter->second;
        // 각 변수 값을 출력합니다.
        printf("{%s : {Send : %d (%d Bytes), Receive: %d (%d Bytes)}}\n", inet_ntoa(ip), transmission.sendPacket, transmission.sendBytes, transmission.recivedPacket, transmission.recivedBytes);
    }

    // 스트림을 종료합니다.
    pcap_close(handle);
    return 0;
}