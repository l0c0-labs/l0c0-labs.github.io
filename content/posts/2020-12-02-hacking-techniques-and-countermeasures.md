---
title: "해킹 기법과 대응방법"
description: "리버스 엔지니어링, 레이스 컨디션, 버퍼 오버플로, 포맷 스트링, 백도어 공격의 정의와 대응 방법을 정리한다."
date: 2020-12-02
categories: [system-security]
language: ko
author: "Inwoo Na"
draft: false
---

## 1. 리버스 엔지니어링 공격

### 1) 정의

리버스 엔지니어링 이란 역공학이라고 불리며 프로그램 등을 분석하여 원하는 동작을 만들어내는 것이다. 리버스 엔지니어링은 학습도구로 사용하거나 악의적인 프로그램(랜섬웨어) 등을 분석하는 긍정적인 쪽으로도 이용되지만 경쟁 업체의 제품을 분석하거나 승인되지 않은 프로그램을 리버스 엔지니어링 하여 불법 복제 프로그램을 만드는 등 악의적인 용도로 사용되는 경우가 있다. 이렇게 악의적인 목적의 리버스 엔지니어링을 리버스 엔지니어링 공격이라고 한다.

### 2) 대응 방법

#### (1) 패킹

패킹은 원본 프로그램을 새로운 파일에 패킹된 형태로 압축, 암호화하여 저장하는 기술이다. 패킹을 이용하면 리버스 엔지니어링을 어렵게 만들 수 있다. [이미지 1]

![이미지 1 : 패킹의 개념](/uploads/hacking-countermeasures/figure-1.jpeg)

[이미지 1 : 패킹의 개념]

#### (2) 안티 디버깅

안티 디버깅은 디버거가 감지되면 실행중인 프로그램을 강제 종료하는 것을 말한다. 안티 디버깅도 두 가지 종류가 있는데, static과 dynamic이 있다.

#### (3) 타이밍 체크

타이밍 체크는 시간이 많이 걸리는 특정 구간을 디버깅 중으로 판단하여 프로그램이나 디버거를 종료시키는 방법이다. 프로세스가 디버깅 중 CPU 연산 시간이 정상적으로 실행되었을 때보다 많이 걸린다는 점에서 착안되었다.

#### (4) 쓰레기코드 넣기

쓰레기코드 넣기는 코드 사이에 의미가 없는 쓰레기 코드(Garbage Code)를 넣고 다단계의 점프문을 섞어 코드를 치환 배치하여 분석이 어렵게 만드는 것이다.

## 2. 레이스 컨디션 공격

### 1) 정의

레이스 컨디션이란 공유 자원에 대해 여러 개의 프로세스가 동시에 접근하기 위해 경쟁하는 상태를 말하는데 이렇게 프로세스들이 경쟁하는 것을 이용하여 관리자 권한으로 실행되는 프로그램 중간에 끼어들어 자신이 원하는 작업을 실행하는 것을 레이스 컨디션 공격이라고 한다.

### 2) 대응 방법

#### (1) 심볼릭 링크 검사 과정 추가

프로그램 로직 중에 임시파일 생성 후, 임시 파일에 접근하기 전에 임시파일에 대한 심볼릭 링크 설정 여부와 권한에 대한 검사과정을 추가한다. [표 1]은 검사 코드의 예시이다.

```c
int safeopen(char *filename) {
    struct stat st, st2;
    int fd;

    // ①
    if (lstat(filename, &st) != 0)
        return -1;
    // ②
    if (!S_ISREG(st.st_mode))
        return -1;
    // ③
    if (st.st_uid != 0)
        return -1;

    fd = open(filename, O_RDWR, 0);
    if (fd < 0)
        return -1;
    // ④
    if (fstat(fd, &st2) != 0) {
        close(fd);
        return -1;
    }
    // ⑤
    if ((st.st_ino != st2.st_ino) || (st.st_dev != st2.st_dev)) {
        close(fd);
        return -1;
    }
    return fd;
}
```

[표 1 : 심볼릭 링크 검사 코드 예]

[표 1]의 코드의 역할은 아래와 같다.

① lstat로 파일의 정보를 확인한다.

② 구조체 st에 대한 st_mode 값으로 파일의 종류에 대해 확인한다.

③ 생성된 파일의 소유자가 root가 아닌 경우 거부하여, 접근하고자 하는 파일이 일반 계정 소유의 파일인지 확인한다.

④ 파일 디스크립터에 의해 열린 파일 정보를 모아 st2 구조체에 전달한다. 전달되는 데이터에는 장치(device), I-노드, 링크 개수, 파일 소유자의 사용자 ID, 소유자의 그룹 ID, 바이트 단위 크기, 마지막 접근 시간, 마지막 수정된 시간, 마지막 바뀐 시간, 파일 시스템 입출력(I/O) 데이터 블록의 크기, 할당된 데이터 블록의 개수 등이 있다.

⑤ 최초 파일 정보를 저장하는 st와 파일을 연 후 st2에 저장된 I-노드 값, 장치(device) 값이 변경되었는지 확인한다.

## 3. 버퍼 오버플로 공격

### 1) 정의

버퍼는 데이터를 전송, 처리하는 동안 일시적으로 보관하는 메모리 영역을 말하고 오버플로는 버퍼가 가지는 최대 크기를 초과하는 것을 말한다. 버퍼 오버플로 공격이란 버퍼에 일정 크기 이상의 데이터를 입력하여 프로그램을 공격하는 것을 말한다.

### 2) 대응 방법

#### (1) 안전한 함수 사용

버퍼 오버플로 공격에 취약한 함수를 사용하지 않는다. 버퍼 오버플로 공격에 취약한 C언어 함수는 [표 2]와 같다.

```c
strcpy(char *dest, const char *src)
strcat(char *dest, const char *src)
getwd(char *buf)
gets(char *s)
fscanf(FILE *stream, const char *format, ...)
scanf(const char *format, ...)
realpath(char *path, char resolved_path[])
sprintf(char *str, const char *format, ...)
```

[표 2 : 버퍼 오버플로 공격에 취약한 함수]

#### (2) 사용자 입출력 최소화

입출력에 대한 사용자의 접근을 최소화하여 공격 가능성을 줄인다. 꼭 필요한 경우 입력 값의 길이를 검사한다. [표 3]은 잘못된 입력 값 검사와 옳은 검사의 예시이다.

**잘못된 strcpy 함수 사용**

```c
void function(char *str) {
    char buffer[20];
    strcpy(buffer, str);
    return;
}
```

**올바른 strncpy 함수 사용**

```c
void function(char *str) {
    char buffer[20];
    strncpy(buffer, str, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = 0;
    return;
}
```

**잘못된 gets 함수 사용**

```c
void function(char *str) {
    char buffer[20];
    gets(buffer);
    return;
}
```

**올바른 fgets 함수 사용**

```c
void function(char *str) {
    char buffer[20];
    fgets(buffer, sizeof(buffer) - 1, stdin);
    return;
}
```

**잘못된 scanf 함수 사용**

```c
int main() {
    char str[80];
    printf("name : ");
    scanf(" %s", str);
    return 0;
}
```

**올바른 scanf 함수 사용**

```c
int main() {
    char str[80];
    printf("name : ");
    scanf(" %79s", str);
    return 0;
}
```

[표 3 : 잘못된 입력 값 검사와 옳은 검사의 예]

#### (3) 실행 가능 공간 보호

스택이나 힙에 저장된 데이터 공간에서 읽기와 쓰기는 가능하게 하고, 실행을 할 수 없게 하는 것. 이를 Non-Executable Stack/Heap라고 하며 실행 가능한 코드를 주입하는 방식의 버퍼 오버플로 방법을 막을 수 있다.

## 4. 포맷 스트링 공격

### 1) 정의

포맷 스트링 공격은 데이터 형태에 대한 불명확한 정의로 인해 발생하는 취약점을 이용해 프로그램을 충돌시키거나 악의적인 코드를 실행 시키는 공격이다.

### 2) 대응 방법

#### (1) 정상적으로 printf 함수 사용

포맷 스트링 공격을 막는 것은 의외로 간단하다. [표 4]와 같이 정상적으로 printf 함수를 사용하면 된다.

```c
printf("%s\n", buffer);
```

[표 4 : 정상적인 printf 함수 사용 예]

아래 [표 5~7]은 취약점을 가질 수 있는 출력 함수의 예시이다.

#### ① fprintf 함수

```c
// fprintf(FILE *fp, const char *fmt, ...)
fp = fopen("/dev/null", "w"); //파일을 쓰기 모드로 오픈
fprintf(fp, "decimal=%d octal = %o", 123, 123);
```

[표 5 : fprintf 함수]

#### ② sprintf 함수

```c
// sprintf(char *str, const char *fmt, ...)
char str[80];
int a = sprintf(str, "decimal=%d octal=%o", 123, 123);
printf("%s", str);
```

[표 6 : sprintf 함수]

#### ③ snprintf 함수

```c
// snprintf(char *str, size_t count, const char *fmt, ...)
```

[표 7: snprintf 함수]

## 5. 백도어 공격

### 1) 정의

백도어(Backdoor)란 영어 그대로 해석하면 ‘뒷문’ 이라는 뜻으로 운영체제나 프로그램을 생성할 때 정상적인 인증 절차를 거치지 않고, 운영체제나 프로그램 등에 접근할 수 있도록 하는 일종의 통로이다. 백도어도 여러 가지 종류가 존재하는데, 서버의 셸을 얻어 관리자로 권한을 상승하는 로컬 백도어, 계정에 패스워드를 입력하고 로그인한 것처럼 원격으로 관리자 권한을 획득하여 시스템에 접근하는 원격 백도어, 인증에 필요한 패스워드를 원격지 공격자에게 보내주는 역할을 하는 패스워드 크래킹 백도어, 시스템 설정을 해커가 원하는 대로 변경하기 위한 시스템 설정 변경 백도어 등이 있다. 백도어를 칭하는 다른 용어는 Administrative hook이나 트랩 도어(Trap Door)가 있다.

### 2) 대응 방법

#### (1) 프로세스 확인

백도어가 시스템에 몰래 작동하고 있는지 확인하기 위해서는 정상적인 프로세스와 아닌 프로세스를 구별하는 것도 매우 중요하다. [표 8]은 윈도우 시스템의 주요 프로세스이다.

| 프로세스 | 역할 |
| --- | --- |
| Csrss.exe(Client/Server Runtime SubSystem | Win 32) : 윈도우 콘솔 관장. 스레드 생성/삭제. 32비트 가상 MS-DOS 모드 지원 |
| Explorer.exe | 작업 표시줄, 바탕 화면 같은 사용자 셸 지원 |
| Lsass.exe(Local Security Authentication Server) | Winlogon 서비스에 필요한 인증 |
| Smss.exe(Session Manager SubSystem) | 사용자 세션 시작 기능, Winlogon, Win32(Csrss.exe)를 구동, 시스템 변수 설정, Smss는 Winlogon이나 Csrss가 끝나기를 기다려 정상적인 Winlogon, Csrss 종료시 시스템 종료 |
| Spoolsv.exe(Printer Spooler Service) | 프린터와 팩스의 스풀링 기능 |
| Svchost.exe(Service Host Process) | DLL(Dynamic Link Libraries)에 의해 실행되는 프로세스의 기본 프로세스, 한 시스템에서 svchost 프로세스 여러 개 볼 수 있음 |
| Services.exe(Service Control Manager) | 시스템 서비스 시작/정지, 그들 간의 상호작용하는 기능 수행 |
| System | 대부분 커널 모드 스레드의 시작점 |

[표 8 : 윈도우 시스템의 주요 프로세스]

#### (2) 열린 포트 확인

백도어의 상당수가 외부(해커)와 통신하기 위해 서비스 포트를 생성하고 열려있다. 윈도우 시스템에서는 netstat 명령으로 열린 포트를 확인 가능하다. 일반적인 시스템에서 사용되는 포트는 그리 많지 않으므로 주의해 살펴보면 백도어로 의심되는 포트를 쉽게 확인 가능하다.

#### (3) SetUID 파일 검사

SetUID 파일은 리눅스나 유닉스 시스템에서 로컬 백도어로 사용될 수 있는 가능성이 크다. 따라서 SetUID 파일 중에 추가 또는 변경된 것이 없는지 주기적으로 살펴봐야 한다.

#### (4) 백신 프로그램과 백도어 탐지 툴 이용

잘 알려진 백도어는 대부분 백신 프로그램이나 탐지 툴에 발견되므로 상기 프로그램을 사용한다.

#### (5) 무결성 검사

무결성 검사란 시스템에 어떤 변화가 일어나는지 테스트하는 것이다. MD5 해시 기법을 많이 사용하며 파일 내용이 조금만 바뀌어도 MD5 해시 결과 값이 다르므로 관리자는 주요 파일의 MD5 해시 값을 주기적으로 수집, 검사하여 파일의 변경 내역을 확인한다.

#### (6) 로그 분석

로그 분석이란 시스템 사용기록 등을 기록한 것을 분석하는 것으로 로그 분석의 방법은 무척 다양하며 사이버 포렌식이라는 하나의 분야로 정착되었다.

## 6. 참고 문헌

운영체제보안 강의자료, 5,6,7,8,9

끝이 없는 배움의 끝, [리버싱] 안티 디버깅, 2017.9.20., https://oopsys.tistory.com/180

D4m0n, Race Condition, 2017.3.26., https://d4m0n.tistory.com/3

위키백과, 포맷 스트링 버그, https://en.wikipedia.org/wiki/Uncontrolled_format_string

ITstory, 버퍼 오버플로 & 포맷 스트링 공격, 2017.4.29., https://copycode.tistory.com/92
