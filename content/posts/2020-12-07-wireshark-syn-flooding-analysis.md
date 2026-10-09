---
title: "Wireshark로 살펴보는 SYN Flooding과 Flooding 공격 유형"
date: 2020-12-07
description: "SYN 요청이 집중된 패킷 덤프를 분석하고 SYN·ACK·RST·FIN·UDP·ICMP·HTTP GET Flooding의 특징을 정리한다."
categories: [network-security]
tags: [wireshark, packet-analysis, ddos, syn-flooding, tcp]
language: ko
author: "Inwoo Na"
draft: false
---

## 1. Wireshark를 이용한 SYN Flooding 패킷 분석

### 다수의 출발지에서 집중되는 SYN 요청

아래 패킷 목록에서는 여러 출발지 IP 주소에서 대상 서버 `192.168.0.2`의 TCP 80번 포트로 SYN 요청을 보내는 모습을 확인할 수 있다. SYN은 TCP 연결 수립을 위한 3-way handshake의 첫 단계에 사용하는 플래그이다.

![여러 출발지 IP에서 대상 서버 80번 포트로 전송되는 SYN 패킷](/uploads/flooding-analysis/figure-1.jpeg)

### 개별 패킷의 TCP 플래그 확인

캡처된 패킷 하나를 열어 상세 정보를 확인하면 TCP Flags가 `0x002 (SYN)`으로 표시된다. Wireshark의 Expert Info에도 연결 수립 요청이며 서버 포트가 80번이라는 설명이 나타난다. 이를 통해 해당 패킷이 대상 서버에 TCP 연결 수립을 요청하는 SYN 패킷임을 확인할 수 있다.

![TCP SYN 플래그와 Expert Info의 연결 수립 요청 표시](/uploads/flooding-analysis/figure-2.jpeg)

### 정상적인 연결 수립 과정과 비교

패킷 목록의 뒷부분에서도 여러 출발지 IP에서 대상 서버의 80번 포트로 SYN 요청을 보내는 패턴이 이어진다. 표시된 목록에서는 서버의 SYN/ACK 응답과 클라이언트의 후속 ACK를 확인하기 어렵다.

![패킷 목록 뒤쪽에서도 이어지는 SYN 요청](/uploads/flooding-analysis/figure-3.jpeg)

정상적인 TCP 연결은 다음 순서로 수립된다.

```text
클라이언트 → 서버: SYN
서버 → 클라이언트: SYN/ACK
클라이언트 → 서버: ACK
```

![정상적인 TCP 3-way handshake의 SYN, SYN/ACK, ACK 패킷 예시](/uploads/flooding-analysis/figure-4.jpeg)

이와 달리 연결이 완료되지 않는 SYN 요청이 반복적으로 집중되는 현상은 SYN Flooding을 의심할 수 있는 패턴이다. 공격자가 출발지 IP를 위조했다면 서버의 SYN/ACK는 위조된 주소로 전송되고, 정상적인 마지막 ACK가 돌아오지 않을 수 있다.

다만 캡처에서 SYN/ACK가 보이지 않는다는 사실만으로 출발지 IP 위조나 서버의 실제 응답 여부를 확정할 수는 없다. 캡처 위치·필터·수집 방향을 확인하고, 양방향 트래픽과 시간당 요청량, 연결 완료율 등을 함께 살펴보아야 한다.

## 2. Flooding 공격 유형

### 1) SYN Flooding

TCP 연결 수립의 첫 단계인 SYN 요청을 악용하는 공격이다. 서버가 SYN을 받고 SYN/ACK를 보낸 뒤 마지막 ACK를 기다리는 동안 연결은 반쯤 열린 상태(half-open)로 남는다.

이러한 요청을 대량으로 발생시키면 서버의 연결 대기 큐(backlog queue)와 관련 자원이 소모되어 정상적인 신규 연결을 받아들이기 어려워질 수 있다. 실제 영향은 서버 구현과 방어 설정에 따라 달라진다.

![SYN 요청이 누적되고 마지막 ACK가 돌아오지 않는 SYN Flooding 예시](/uploads/flooding-analysis/figure-5.jpeg)

이미지 출처: [Peemang IT — SYN Flooding 설명](https://peemangit.tistory.com/210).

### 2) ACK Flooding

TCP ACK 플래그(`0x10`)가 설정된 패킷을 대량으로 전송하여 대상이나 중간 네트워크 장비의 자원을 소모시키는 공격이다. 정상적인 연결 상태와 일치하지 않는 ACK 패킷도 포함될 수 있다.

이러한 트래픽은 대역폭과 패킷 처리 자원, 방화벽의 상태 검사 처리에 부담을 줄 수 있다. 수신 측의 응답은 연결 상태와 구현에 따라 달라지며, ACK마다 RST와 ICMP 응답이 동시에 발생한다고 일반화할 수는 없다.

![ACK Flooding 패킷 예시](/uploads/flooding-analysis/figure-6.jpeg)

이미지 출처: [MazeBolt — ACK Flood](https://kb.mazebolt.com/knowledgebase/ack-flood/).

### 3) RST Flooding

TCP 연결을 초기화하거나 종료하는 데 사용하는 RST 패킷을 대량으로 전송하는 공격이다. 패킷 처리 자원을 소모시키거나, 유효한 연결에 대한 RST가 수용될 경우 세션을 중단시킬 수 있다.

다만 임의의 RST 패킷이 모든 연결을 종료하는 것은 아니다. 연결 정보와 시퀀스 번호 등 TCP 검증 조건에 따라 수용 여부가 달라진다.

![RST Flooding 패킷 예시](/uploads/flooding-analysis/figure-7.jpeg)

이미지 출처: [MazeBolt — RST Flood](https://kb.mazebolt.com/knowledgebase/rst-flood/).

### 4) FIN Flooding

TCP FIN 플래그(`0x01`)가 설정된 패킷을 대량으로 전송하는 공격이다. FIN은 정상적인 연결 종료에도 사용되지만, 비정상적인 대량 트래픽은 서버나 상태 기반 네트워크 장비의 처리 자원을 소모시킬 수 있다.

![FIN Flooding 패킷 예시](/uploads/flooding-analysis/figure-8.jpeg)

이미지 출처: [MazeBolt — FIN Flood](https://kb.mazebolt.com/knowledgebase/fin-flood/).

### 5) UDP Flooding

대상에 많은 UDP 패킷을 전송하여 네트워크 대역폭과 처리 자원을 소모시키는 공격이다. UDP는 연결 수립 절차가 없으므로 TCP와 같은 handshake 없이 데이터그램이 전달된다.

여러 호스트에서 발생하는 DDoS 형태로 이루어질 수 있지만, 단일 송신지에서도 송신량과 대상의 처리 용량에 따라 영향을 줄 수 있다.

![UDP Flooding 패킷 예시](/uploads/flooding-analysis/figure-9.jpeg)

이미지 출처: [MazeBolt — UDP Flood](https://kb.mazebolt.com/knowledgebase/udp-flood/).

### 6) ICMP Flooding

ICMP Echo Request, 즉 ping 요청 등을 대량으로 보내 대상의 대역폭과 패킷 처리 자원을 소모시키는 공격이다. 요청을 처리하고 응답하는 과정도 부담을 줄 수 있다.

영향은 단순히 송신 측과 수신 측 대역폭의 크기만으로 결정되지 않는다. 패킷 전송률과 크기, 대상의 처리 능력과 제한 정책도 함께 작용한다.

![ICMP Echo Request를 이용한 Flooding 패킷 예시](/uploads/flooding-analysis/figure-10.jpeg)

이미지 출처: [MazeBolt — ICMP Ping Flood](https://kb.mazebolt.com/knowledgebase/icmp-ping-flood/).

### 7) HTTP GET Flooding

웹서버에 HTTP GET 요청을 반복적으로 보내 응답 처리에 필요한 자원을 소모시키는 공격이다. 같은 URL이나 여러 URL에 요청이 집중될 수 있다.

정상적인 TCP 연결과 정상 요청처럼 보이는 HTTP 메시지를 이용할 수 있으므로, 패킷 형식만으로 구분하기 어려운 경우가 있다. 웹서버의 연결·작업 처리 용량뿐 아니라 애플리케이션 로직이나 데이터베이스 처리에도 부하가 발생할 수 있다.

![HTTP GET Flooding 요청 예시](/uploads/flooding-analysis/figure-11.jpeg)

이미지 출처: [Security04 — HTTP GET Flooding 설명](https://security04.tistory.com/136).

## 참고문헌

- 보안의 모든 것(2010.06.25.), 「TCP FIN Flooding」, 원문 주소: `http://blog.daum.net/sword28/40`.
- 지빵네(2018.06.15.), [DDoS 공격 유형 정리 #1](https://jihwan4862.tistory.com/122).
- Just Blue(2011.08.04.), [DDoS 공격 유형에 따른 분류](https://m.blog.naver.com/twers/50117453084).
- 한국과학기술정보연구원(2015.12.), [DDoS 공격 유형별 분석보고서](https://repository.kisti.re.kr/bitstream/10580/6252/1/2015-083%20DDoS%20%EA%B3%B5%EA%B2%A9%20%EC%9C%A0%ED%98%95%EB%B3%84%20%EB%B6%84%EC%84%9D%EB%B3%B4%EA%B3%A0%EC%84%9C.pdf).
- [RFC 4987 — TCP SYN Flooding Attacks and Common Mitigations](https://www.rfc-editor.org/rfc/rfc4987).
