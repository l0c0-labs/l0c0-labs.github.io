---
title: "Flooding 공격 분석 및 정리"
date: 2020-12-07
categories: [network-security]
language: ko
author: "Inwoo Na"
draft: false
---

## 1. 와이어샤크를 이용한 SYN Flooding 패킷 분석

1) [이미지 1]의 패킷을 보면 불특정한 다량의 IP(①)에서 피해자(②)의 IP의 80포트(③)로 TCP 3way handshaking 과정중 하나인 SYN(④) 요청을 보내고 있다.

![이미지 1 : 패킷 확인](/uploads/flooding-analysis/figure-1.jpeg)

[이미지 1 : 패킷 확인]

2) [이미지 2]는 [이미지 1]에서 캡처된 패킷중 하나를 열어 상세보기 한 것이다. 보다시피 Flag가 Syn (①)이고 Expert Info(②)에도 마찬가지로 “Connection establish request (SYN) server port 80“으로 표시되어 대상 서버의 80포트로 SYN 연결 수립을 요청한 것임을 확신할 수 있다.

![이미지 2 : 패킷 상세 확인](/uploads/flooding-analysis/figure-2.jpeg)

[이미지 2 : 패킷 상세 확인]

3) 패킷의 끝부분까지 확인해 보아도 [이미지 3], 불특정한 다량의 IP(①) 에서 서버(②)의 80포트(③)로 SYN(④) 요청을 하는 것만 보이고 서버(②) 에서 클라이언트(①)로의 SYN/ACK 응답은 단 한 개도 보이지 않는다. 정상적인 TCP 3way handshaking 과정이라면 [이미지 4]와 같이 클라이언트 SYN -> 서버 SYN/ACK -> 클라이언트 ACK로 이루어져야 하나 패킷에는 다량의 IP에서 피해자의 IP로 SYN 요청을 하는 것만 보인다. 출발지 IP(①)가 공격자가 Spoofing한 IP일 가능성이 있지만, 캡처된 패킷만으로는 서버의 SYN/ACK 응답 여부나 IP Spoofing을 확신할 수 없다. 그러므로 이 패킷에서는 SYN Flooding 공격이 의심된다.

![이미지 3 : 패킷 확인](/uploads/flooding-analysis/figure-3.jpeg)

[이미지 3 : 패킷 확인]

![이미지 4 : 정상적인 TCP 3Way handshaking 과정 예시](/uploads/flooding-analysis/figure-4.jpeg)

[이미지 4 : 정상적인 TCP 3Way handshaking 과정 예시]

## 2. 각종 Flooding 공격 정리

### 1) SYN Flooding

TCP 3 Way handshaking의 처음 단계인 SYN 요청을 악용하여 서버로 다량의 SYN 패킷을 전송하여 피해 서버의 대기 큐(Backlog Queue)를 가득 차게 만들어 이후 들어오는 연결요청을 받아들일 수 없도록 만드는 공격. SYN 패킷만 전송하고 SYN/ACK에 대한 응답인 ACK 패킷을 전송하지 않으면 Half Open 상태가 되는데, 이때 계속해서 SYN을 보내 Backlog Queue를 가득 채워 더 이상의 TCP 신규 접속을 받지 못하게 만든다. [이미지 5]

![이미지 5 : SYN Flooding 공격 과정의 예시](/uploads/flooding-analysis/figure-5.jpeg)

[이미지 5 : SYN Flooding 공격 과정의 예시, 출처 : https://peemangit.tistory.com/210]

### 2) ACK Flooding

ACK Flooding은 연결된 TCP 세션이 없는 상태에서 TCP Header의 Flags를 ACK (0x10)로 설정하고 변조된 발신 IP로 무작위로 대상에게 ACK 패킷을 보내면 수신측에서 변조된 IP로 RST 패킷을 보내는 등의 처리로 수신측의 시스템에 과부하를 초래시키는 공격이다. [이미지 6]

![이미지 6 : ACK Flooding 공격 패킷의 예시](/uploads/flooding-analysis/figure-6.jpeg)

[이미지 6 : ACK Flooding 공격 패킷의 예시, 출처 : https://kb.mazebolt.com/knowledgebase/ack-flood/]

### 3) RST Flooding

RST Flooding은 TCP 연결을 강제로 종료시키는 RST 패킷을 대량으로 전송하는 공격으로, 해당 세션의 검증 조건을 만족하는 패킷은 실제 연결된 세션을 단절시킬 수 있는 공격이다. [이미지 7]

![이미지 7 : RST Flooding 공격 패킷의 예시](/uploads/flooding-analysis/figure-7.jpeg)

[이미지 7 : RST Flooding 공격 패킷의 예시, 출처 : https://kb.mazebolt.com/knowledgebase/rst-flood/]

### 4) FIN Flooding

Fin Flooding은 TCP Header의 Flags를 FIN(0x01)으로 설정하여 대량의 패킷을 보내 서버가 이를 처리하기 위해 대부분의 자원을 소모하게 만들어 정상적인 서비스를 불가하게 만드는 공격이다. [이미지 8]

![이미지 8 : FIN Flooding 공격 패킷의 예시](/uploads/flooding-analysis/figure-8.jpeg)

[이미지 8 : FIN Flooding 공격 패킷의 예시, 출처 : https://kb.mazebolt.com/knowledgebase/fin-flood/]

### 5) UDP Flooding

UDP Flooding은 UDP의 비연결성 및 비 신뢰성을 이용한 공격의 한 종류로써 많은 수의 UDP 패킷을 대상에게 전송하여 네트워크의 대역폭(bandwidth)을 소모시켜 정상적인 서비스가 불가능하도록 하는 공격이다. 단일 호스트의 효과는 공격 규모와 대상의 처리 능력에 따라 다르며, 주로 DDoS 공격으로 이루어진다. [이미지 9]

![이미지 9 : UDP flooding 공격 패킷의 예시](/uploads/flooding-analysis/figure-9.jpeg)

[이미지 9 : UDP flooding 공격 패킷의 예시, 출처 : https://kb.mazebolt.com/knowledgebase/udp-flood/]

### 6) ICMP Flooding

ICMP Flooding은 대상 시스템에 막대한 양의 ICMP 에코 요청 패킷(ping 패킷)을 보내는 방법이다. 대상 시스템에 부하를 일으키기 위해서는 ping을 보내는 양과 대상 시스템의 네트워크 대역폭 및 처리 능력을 함께 고려해야 한다. [이미지 10]

![이미지 10 : ICMP Flooding 공격 패킷의 예시](/uploads/flooding-analysis/figure-10.jpeg)

[이미지 10 : ICMP Flooding 공격 패킷의 예시, 출처 : https://kb.mazebolt.com/knowledgebase/icmp-ping-flood/]

### 7) HTTP GET Flooding

HTTP GET Flooding은 동일한 URL에 Get 요청을 반복하여 웹서버가 클라이언트에게 응답(Response)을 하기 위해 서버 자원을 사용하는 것을 악용하여 서버의 자원을 초과시키는 공격이다.

* 웹서버는 한정된 HTTP Connection을 가지기 때문에 용량 초과 시 정상적인 서비스가 어렵다.

공격을 당하는 서버는 정상적인 TCP 세션과 함께 정상적으로 보이는 HTTP Get 요청을 지속적으로 처리해야한다. 이 경우 HTTP 처리 모듈의 과부하 까지도 야기할 수 있다. [이미지 11]

![이미지 11 : HTTP GET Flooding 공격 패킷의 예시](/uploads/flooding-analysis/figure-11.jpeg)

[이미지 11 : HTTP GET Flooding 공격 패킷의 예시, 출처 : https://security04.tistory.com/136]

## 3. 참고문헌

1) 보안의 모든 것, TCP FIN Flooding, 2010. 6. 25., http://blog.daum.net/sword28/40

2) 지빵네, DDoS 공격 유형 정리#1, 2018. 6. 15, https://jihwan4862.tistory.com/122

3) [Just Blue], DDoS 공격 유형에 따른 분류, 2011. 8. 4. https://m.blog.naver.com/twers/50117453084

4) 한국과학기술정보연구원, 2015.12, DDoS 공격 유형별 분석보고서,

https://repository.kisti.re.kr/bitstream/10580/6252/1/2015-083%20DDoS%20%EA%B3%B5%EA%B2%A9%20%EC%9C%A0%ED%98%95%EB%B3%84%20%EB%B6%84%EC%84%9D%EB%B3%B4%EA%B3%A0%EC%84%9C.pdf
