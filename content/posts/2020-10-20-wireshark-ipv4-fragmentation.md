---
title: "Wireshark를 이용한 IPv4 단편화 패킷 분석"
date: 2020-10-20
description: "MTU 1500 환경에서 ping으로 IPv4 단편화를 발생시키고, Wireshark에서 식별자·플래그·오프셋과 재조립 결과를 확인한다."
categories: [network-security]
tags: [wireshark, ipv4, fragmentation, packet-analysis, icmp]
language: ko
author: "Inwoo Na"
draft: false
---

Wireshark를 이용하여 IPv4 단편화 패킷을 분석하려고 한다. 먼저 IPv4 헤더의 주요 필드를 정리한 뒤, ping을 이용해 단편화를 발생시키고 캡처한 패킷을 확인한다.

## 1. IPv4 헤더와 단편화 관련 필드

![IPv4 헤더의 필드 구성](/uploads/ipv4-fragmentation/ipv4-header.jpeg)

### 버전(Version)

IP의 버전을 나타내는 4비트 필드이다. IPv4의 값은 `0100`, IPv6의 값은 `0110`이다. 버전에 따라 헤더 구성이 달라지므로 올바른 해석을 위해 버전 정보가 필요하다. 아래 설명은 IPv4 헤더를 기준으로 한다.

### 헤더 길이(Header Length)

IPv4의 IHL 필드는 헤더 길이를 4바이트 단위로 표현한다. 최소 헤더 길이는 20바이트이며, 최댓값은 `(2^4 - 1) × 4 = 60바이트`이다. 옵션이 없는 경우 IHL은 5이며, 헤더 길이는 20바이트이다.

### 서비스 타입(Type of Service)

서비스 품질과 관련된 처리를 위해 사용하는 필드이다. 현재는 DSCP와 ECN으로 나누어 해석한다. QoS(Quality of Service)는 네트워크에서 전송률, 지연, 오류율 등과 관련된 서비스 품질을 의미한다.

### 전체 길이(Total Length)

IPv4 헤더와 데이터 길이를 합한 값이다. 16비트 필드이므로 최댓값은 `2^16 - 1 = 65535바이트`이다.

```text
IPv4 데이터 길이 = Total Length - IPv4 헤더 길이
```

### 식별자(Identification)

단편화된 데이터그램을 재조립할 때 사용하는 식별 값이다. 동일한 원본 데이터그램에서 나뉜 단편들은 같은 식별자를 가진다. 재조립 시에는 식별자뿐 아니라 발신지·목적지 주소와 프로토콜도 함께 확인한다.

### 플래그(Flags)

3비트 필드이며 예약 비트와 다음 두 플래그로 구성된다.

- **DF(Don't Fragment)**: 1이면 단편화를 허용하지 않는다. 0이면 필요할 때 단편화할 수 있다.
- **MF(More Fragments)**: 1이면 뒤에 이어지는 단편이 있다. 0이면 마지막 단편이거나 단편화되지 않은 데이터그램이다.

### 단편 오프셋(Fragment Offset)

원본 IPv4 데이터에서 해당 단편 데이터가 시작하는 위치를 나타낸다. 헤더의 필드 값은 **8바이트 단위**이다.

첫 번째 단편의 오프셋은 0이다. 첫 단편의 데이터 길이가 800바이트라면 다음 단편의 헤더에 저장되는 오프셋 값은 `800 ÷ 8 = 100`이다.

Wireshark는 오프셋을 바이트 위치로 환산하여 표시하므로, 화면의 `1480`은 헤더에 저장된 값 `185`에 해당한다.

### 수명(Time to Live, TTL)

패킷이 네트워크에서 무한히 순환하지 않도록 수명을 제한하는 필드이다. 라우터를 지날 때 감소하며, TTL이 소진되면 패킷을 폐기한다. 초기값은 운영체제와 설정에 따라 달라진다.

### 프로토콜(Protocol)

IPv4 데이터에 실린 상위 프로토콜을 나타낸다. 이 실습에서 사용하는 ICMP의 프로토콜 번호는 1이다.

### 헤더 체크섬(Header Checksum)

IPv4 **헤더**의 오류를 확인하는 데 사용한다. IPv4 데이터 전체를 검사하는 체크섬은 아니다.

### 발신지 주소와 목적지 주소

Source Address는 발신지 IPv4 주소이고, Destination Address는 목적지 IPv4 주소이다.

## 2. ping을 이용한 단편화 과정 확인

### 1) MTU 확인

Windows 명령 프롬프트에서 다음 명령으로 네트워크 인터페이스의 MTU를 확인한다.

```bat
netsh interface ipv4 show subinterfaces
```

실습에 사용한 Wi-Fi 인터페이스의 MTU는 1500바이트이다.

![Wi-Fi 인터페이스의 MTU가 1500으로 표시된 명령 결과](/uploads/ipv4-fragmentation/mtu.png)

### 2) 패킷 캡처 시작

Wireshark를 실행하고 사용 중인 네트워크 인터페이스를 더블클릭하여 패킷 캡처를 시작한다.

![Wireshark에서 Wi-Fi 캡처 인터페이스 선택](/uploads/ipv4-fragmentation/capture-interface.jpeg)

### 3) 게이트웨이 확인

명령 프롬프트에서 `ipconfig`를 실행하여 인터페이스 주소와 기본 게이트웨이를 확인한다. 실습 환경의 IPv4 주소는 `192.168.0.6`, 기본 게이트웨이는 `192.168.0.1`이다.

```bat
ipconfig
```

![IPv4 주소 192.168.0.6과 기본 게이트웨이 192.168.0.1 확인](/uploads/ipv4-fragmentation/ipconfig.png)

### 4) ping 전송

기본 게이트웨이에 4048바이트의 데이터를 담은 ICMP Echo Request를 한 번 전송한다.

```bat
ping 192.168.0.1 -l 4048 -n 1
```

`-l`은 데이터 크기, `-n`은 전송 횟수를 지정한다. 전송할 데이터그램이 인터페이스 MTU보다 크므로 여러 IPv4 단편으로 나뉜다.

![4048바이트 ping을 게이트웨이에 한 번 전송한 결과](/uploads/ipv4-fragmentation/ping.jpeg)

### 5) Frame 1 확인

첫 번째 프레임은 IPv4이며, Total Length는 1500바이트로 인터페이스의 MTU와 일치한다. IPv4 헤더가 20바이트이므로 이 단편의 데이터 길이는 1480바이트이다.

- Identification: `0x1247`
- Fragment Offset: `0바이트`
- More Fragments: `Set`
- 원본 IPv4 데이터에서의 범위: `0~1479`
- 목적지: `192.168.0.1`

오프셋이 0이므로 첫 단편이며, MF가 설정되어 있으므로 뒤에 이어지는 단편이 있다.

![첫 단편의 식별자, 전체 길이, MF 플래그와 오프셋](/uploads/ipv4-fragmentation/frame-1.jpeg)

### 6) Frame 2 확인

식별자가 첫 단편과 같은 `0x1247`이며, 발신지·목적지 주소와 프로토콜도 일치한다. Wireshark에 표시되는 Fragment Offset은 1480바이트이다.

- Total Length: `1500바이트`
- Fragment Offset: `1480바이트` — 헤더 필드 값은 `185`
- More Fragments: `Set`
- 데이터 길이: `1480바이트`
- 원본 IPv4 데이터에서의 범위: `1480~2959`

MF가 설정되어 있으므로 마지막 단편은 아니다.

![두 번째 단편의 오프셋 1480과 MF 플래그](/uploads/ipv4-fragmentation/frame-2.jpeg)

### 7) Frame 3 확인과 재조립

세 번째 단편도 같은 식별자 `0x1247`을 가진다. Fragment Offset은 2960바이트이며, MF는 설정되어 있지 않으므로 마지막 단편이다.

- Total Length: `1116바이트`
- Fragment Offset: `2960바이트` — 헤더 필드 값은 `370`
- More Fragments: `Not Set`
- 데이터 길이: `1096바이트`
- 원본 IPv4 데이터에서의 범위: `2960~4055`

![세 번째 단편과 Wireshark의 IPv4 재조립 결과](/uploads/ipv4-fragmentation/frame-3.jpeg)

세 단편의 데이터를 합하면 다음과 같다.

```text
1480 + 1480 + 1096 = 4056바이트
4048바이트(ping 데이터) + 8바이트(ICMP 헤더) = 4056바이트
```

Wireshark의 `Reassembled IPv4 length: 4056`은 재조립된 IPv4 데이터 부분의 크기이다. 여기에 IPv4 헤더 20바이트를 더하면 원본 IPv4 데이터그램의 전체 길이는 4076바이트가 된다.

| 프레임 | IPv4 전체 길이 | 단편 데이터 길이 | 오프셋(바이트) | 헤더 오프셋 값(8바이트 단위) | MF |
| --- | --- | --- | --- | --- | --- |
| 1 | 1500 | 1480 | 0 | 0 | 1 |
| 2 | 1500 | 1480 | 1480 | 185 | 1 |
| 3 | 1116 | 1096 | 2960 | 370 | 0 |

## 참고문헌

- 정보통신기술용어해설(2018.05.28.), [IPv4 Header — IPv4 헤더](http://ktword.co.kr/abbr_view.php?m_temp1=1859).
- 「패킷의 이해, Ethernet 프레임」(2015.03.30.), [IP 헤더](https://m.blog.naver.com/sujunghan726/220315439853).
- 정보통신기술용어해설(2018.05.28.), [IP Fragmentation — IP 단편화](http://www.ktword.co.kr/abbr_view.php?m_temp1=5236&id=1003).
- 「[패킷 분석] IP fragments」(2014.04.12.), [블로그 글](http://blog.naver.com/shj1126zzang/90193887664).
- 「ping 단편화 과정 [실습]」(2013.01.23.), [실습 글](https://iplab5085.tistory.com/entry/ping-단편화-과정-실습).
- [RFC 791 — Internet Protocol](https://www.rfc-editor.org/rfc/rfc791).
