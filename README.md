# WHS 3기 네트워크 보안 과제 - PCAP_programming

작성자 : 화이트햇스쿨 3기 8반 류석준
<br>
작성일 : 2025.04.01.
<br>
<br>
C, C++ 기반 **PCAP API**를 활용하여 **PACKET의 정보를 출력**하는 프로그램을 작성했다. 출력되는 주요 PACKET 정보는 다음과 같다.
<br>
- **Ethernet Header**: Source MAC / Destination MAC
- **IP Header**: Source IP / Destination IP
- **TCP Header**: Source Port / Destination Port
- **PACKET Message** (최대 16바이트 출력)
<br>
본 프로그램은 이더넷(eth0) 인터페이스에서 실시간으로 패킷을 캡처하고, 캡처된 패킷에서 이더넷, IP 및 TCP 헤더를 분석하여 MAC 주소, IP 주소, 포트 번호와 함께 Message도 출력하는 코드이다.
