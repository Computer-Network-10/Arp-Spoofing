# Arp-Spoofing

### 실행시 요구사항
1. arping 설치 필요
2. mac os에서만 작동 가능 


arping 명령어와 ifconfig 명령어를 사용하기 때문에, mac os에서만 정확하게 작동할 수 있습니다. <br>
하지만 코드를 조금만 수정한다면 다른 운영체제에서도 쉽게 사용할 수 있을 것입니다.
<br>
<br>
<br>





```
brew install arping
arping -v
```
<br>
만약 버전이 제대로 뜨지 않는다면 환경변수 설정이 안되어있는 문제입니다.
<br>


<br>
다음 명령어로 컴파일 할 수 있습니다.
<br>

```
g++ -o arp_spoofing arp_spoofing.cpp -lpcap
```

<br><br>


[프로젝트 설명 블로그 링크](https://white-hack.tistory.com/entry/ARP-spoofing-1-ARP-spoofing-%ED%94%84%EB%A1%9C%EC%A0%9D%ED%8A%B8-%EC%8B%9C%EC%9E%91%ED%95%98%EA%B8%B0) : 더욱 자세한 설명은 링크를 참고해주세요.

