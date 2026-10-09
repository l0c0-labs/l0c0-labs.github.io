---
title: "와이어샤크를 이용한 단편화 패킷 분석"
date: 2020-10-20
categories: [network-security]
language: ko
author: "Inwoo Na"
draft: false
---

와이어샤크를 이용하여 단편화 패킷을 분석하려고 한다. 단편화 패킷에서 사용되는 IP헤더의 데이터 그램에 대한 세부설명은 아래와 같다.

## 1. 단편화에서 사용되는 프로토콜(IP헤더 데이터 그램) 정리

![IP데이터 그램의 사진](/uploads/ipv4-fragmentation/ipv4-header.jpeg)

[IP데이터 그램의 사진]

### 1) 버전(Version)

IP의 버전을 의미하며 4비트의 크기를 가지고 있다. IPv4 = 0100, IPv6 = 0110

버전에 따라 헤더의 구성이 달라지므로, 올바른 해석을 위해 IP버전정보가 필요하다. 버전이 맞지 않는 경우에는 폐기한다.

### 2) 헤더길이(Header Length)

4바이트 단위로 표현하고 최소길이는 20바이트, 최대 표현 가능한 길이는 (2^4 –1) * 4 = 60바이트이다. 실제값은 4바이트 단위로 들어간다.

### 3) 서비스 타입

QoS(Quality of Service)를 제공할 때 사용함. QoS란 인터넷이나 네트워크상에서 전송률, 에러율과 관련된 서비스의 품질을 의미한다.

### 4) 전체길이 (Total Length)

헤더와 데이터의 길이를 합한 길이이며 전체 길이의 최댓값은 2^16 – 1인 65535이다. 데이터의 길이 = 전체길이 – 헤더길이

헤더 길이는 20~60바이트이며 지정하지 않았을시 20바이트이다.

### 5) 식별자(Identification)

데이터 그램이 단편화되어 전송된 후, 재조립할 때 이용됨.

식별자 필드는 중복되지 않아야하며 재조립 대상에서 구분되어야함.

모든 단편화된 단편의 헤더에는 식별자 필드가 포함된다.

### 6) 플래그(Flag)

데이터 그램의 상태나 진위를 나타내기 위한 변수, 두가지가 있으며 종류는

- Do not Fragment (1이면 단편화를 하지 않고, 0이면 단편화를 허용함)
- More Fragment (1이면 마지막 단편이 아님, 0이면 마지막 단편)

### 7) 단편화 오프셋(Fragmentation Offset)

전체 데이터 그램에서 해당 단편 데이터의 시작 위치이다. 8바이트 단위로 표시한다.

예) 첫 번째 단편의 오프셋 값은 0 = 첫 번째 단편이므로 시작 위치가 0임

예) 두 번째 단편부터는 이전에 단편화된 길이를 8로 나누어 계산 = 만약, 첫 번째가 800바이트였다면 두 번째 단편화 오프셋값은 100이다.

### 8) 수명(Time to Live)

데이터 그램의 수명제한을 위해 사용한다. 홉수로 수명을 표시하며 라우터가 데이터 그램을 처리할 때마다 1홉씩 감소시킨다. 보내는 곳에서 수명 값을 지정하여 보내며 초기값은 운영체제와 설정에 따라 달라진다. 데이터 그램들의 송수신 과정에서 상위계층 프로토콜을 혼란시킬 수 있으므로, 홉수가 0이 되면 라우터에서 데이터 그램을 폐기한다.

### 9) 프로토콜(Protocol)

데이터 그램을 처리한 후, 전달될 상위 프로토콜을 표시한다. Internet Protocol은 다양한 상위프로토콜을 다중화, 역다중화 하기 때문에 필요하다.

### 10) 체크섬(Checksum)

수신한 IP 헤더 내의 에러 여부 체크용도이다.

### 11) 발신지주소(Source Address)

발신지의 IP주소이다.

### 12) 목적지주소(Destination Address)

목적지의 IP주소이다.

## 2. ping을 이용한 단편화 과정 확인

### 1) MTU 확인

cmd에서 “netsh interface ipv4 show subinterfaces”로 MTU 확인 = 1500이다. [사진 1]

![사진 1](/uploads/ipv4-fragmentation/mtu.png)

[사진 1]

### 2) 패킷 캡처 시작

와이어샤크를 켜고 사용하는 랜카드를 더블클릭하여 패킷 캡처를 시작한다. [사진 2]

![사진 2](/uploads/ipv4-fragmentation/capture-interface.jpeg)

[사진 2]

### 3) 게이트웨이 확인

cmd를 실행한 뒤 ipconfig로 랜카드의 게이트웨이를 확인한다. 192.168.0.1 [사진 3]

![사진 3](/uploads/ipv4-fragmentation/ipconfig.png)

[사진 3]

### 4) ping 전송

`ping 192.168.0.1 -l 4048 -n 1`로 게이트웨이에 4048 바이트 핑 1회 전송. [사진 4]

![사진 4](/uploads/ipv4-fragmentation/ping.jpeg)

[사진 4]

### 5) Frame 1 확인

Frame Number : 1로 Frame 1번, Version이 0100으로 IPv4인 것을 확인하였고 Total Length가 1500으로 1)에서 확인한 MTU와 일치한다. Fragment offset이 0으로 첫 번째 단편화 오프셋이며, Flag는 More fragments : Set으로 마지막 단편화 패킷이 아니다. 페이로드는 0~1479 까지. 도착지의 주소가 3)에서 확인한 게이트웨이로 찾던 패킷과 일치하다.

![사진 5](/uploads/ipv4-fragmentation/frame-1.jpeg)

[사진 5]

### 6) Frame 2 확인

식별자(Identification)가 0x1247로 5)와 일치하여 같은 단편화 패킷이며 Fragment offset이 1480바이트(헤더 값 185)로 두 번째 단편화 오프셋임. Flag는 More fragments : Set으로 마지막 단편화 패킷이 아니다. 페이로드는 1480~2959까지.  [사진 6]

![사진 6](/uploads/ipv4-fragmentation/frame-2.jpeg)

[사진 6]

### 7) Frame 3 확인

Identification이 0x1247로 6)과 일치하여 같은 단편화 패킷이며 Fragment offset이 2960바이트(헤더 값 370)로 세 번째 단편화 오프셋이다. Flag값은 More fragments가 Not Set이므로 마지막 단편화 패킷이며 페이로드는 2960~4055까지. 재조립한 크기가 (Reassembled IPv4 length : 4056) 4056으로 표시되는 이유는 4)에서 보낸 데이터에 8바이트의 ICMP 헤더가 붙기 때문이다. [사진 7]

![사진 7](/uploads/ipv4-fragmentation/frame-3.jpeg)

[사진 7]

## 3. 참고문헌

1) 정보통신기술용어해설, 20180528, IPv4 Header IPv4 헤더 http://ktword.co.kr/abbr_view.php?m_temp1=1859

2) 패킷의 이해, Ethernet 프레임, 20150330, IP 헤더, https://m.blog.naver.com/sujunghan726/220315439853

3) 정보통신기술용어해설, 20180528, IP Fragmentation, IP Segmentation IP 단편화, IP 조각화, IPv4 단편화, IPv6 단편화, http://www.ktword.co.kr/abbr_view.php?m_temp1=5236&id=1003

4) [패킷 분석] IP fragments, 20140412, http://blog.naver.com/shj1126zzang/90193887664

5) ping 단편화 과정 [실습], 20130123, https://iplab5085.tistory.com/entry/ping-%EB%8B%A8%ED%8E%B8%ED%99%94-%EA%B3%BC%EC%A0%95-%EC%8B%A4%EC%8A%B5
