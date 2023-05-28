# Arp-Spoofing

### 실행시 요구사항
1. arping 설치 필요
```
brew install arping
arping -v
```

만약 버전이 제대로 뜨지 않는다면 환경변수 설정이 안되어있는 문제입니다.
다음 명령어로 컴파일 할 수 있습니다.
```
g++ -o arp_spoofing arp_spoofing.cpp -lpcap
```

