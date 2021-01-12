# suricata-rule
* snort(suricata) rule 파일을 제작하여 특정 사이트 트래픽을 탐지하여라.

## Description
https://suricata.readthedocs.io/en/suricata-6.0.0/rules/

이번 과제에서는 HTTP/HTTPS 과 함께 TCP, SSH 등도 같이 탐지해 보았습니다.

### Rule 1
```
alert http any any -> $HOME_NET 80 (msg:"/ access"; http.uri; content:"/"; sid:1; rev:1;)
```

`http://mineta.kr/` 로 요청이 들어오는 것을 탐지합니다.

### Rule 2
```
alert http any any -> $HOME_NET 80 (msg:"/blog access"; http.uri; content:"/blog"; sid:2; rev:1;)
```

`http://mineta.kr/blog` 로 요청이 들어오는 것을 탐지합니다.

### Rule 3
```
alert http $HOME_NET 80 -> any any (msg:"404 Not Found"; http.stat_code; content:"404"; sid:3; rev:1;)
```

서버가 HTTP status code 404로 응답하는 것을 탐지합니다.

### Rule 4
```
alert http any any -> $HOME_NET 80 (msg:"/admin access - SQL Injection suspicious?"; http.uri; content:"/admin"; http.request_body; content:"%27"; sid:4; rev:1;)
```

/admin 페이지에서, POST로 요청한 데이터에 SQL Injection 시도로 의심되는 입력(문자 quote)이 들어오는 것을 탐지합니다.

### Rule 5
```
alert http any any -> $HOME_NET 80 (msg:"Googlebot access"; http.user_agent; content:"Googlebot"; sid:5; rev:1;)
```

Google 크롤러(Googlebot)가 웹 페이지를 요청하는 것을 탐지합니다. (User-Agent 기반)

### Rule 6
```
alert http $HOME_NET any -> 93.184.216.34 80 (msg:"http://example.org request"; sid:6; rev:1;)
```

서버가 http://example.org 에 요청을 보내는 것을 탐지합니다.

### Rule 7
```
alert http $HOME_NET any -> 211.233.50.244 80 (msg:"http://reversing.kr request"; sid:7; rev:1;)
```

서버가 http://reversing.kr 에 요청을 보내는 것을 탐지합니다.

### Rule 8
```
alert http $HOME_NET any -> 128.61.240.205 80 (msg:"http://pwnable.kr request"; sid:8; rev:1;)
```

서버가 http://pwnable.kr 에 요청을 보내는 것을 탐지합니다.

### Rule 9
```
alert http $HOME_NET any -> 151.101.189.176 80 (msg:"http://cdn.kernel.org/pub/linux/kernel/ request"; http.uri; content:"/pub/linux/kernel/"; sid:9; rev:1;)
```

서버가 http://cdn.kernel.org/pub/linux/kernel/ 에 요청을 보내는 것을 탐지합니다.

### Rule 10
```
alert https $HOME_NET any -> 139.162.122.119 443 (msg:"https://pwnable.tw request"; sid:10; rev:1;)
```

서버가 https://pwnable.tw 에 요청을 보내는 것을 탐지합니다.

### Rule 11
```
alert https $HOME_NET any -> 162.243.137.82 443 (msg:"https://pwnable.xyz request"; sid:11; rev:1;)
```

서버가 https://pwnable.xyz 에 요청을 보내는 것을 탐지합니다.

### Rule 12
```
alert https $HOME_NET any -> 101.101.164.176 443 (msg:"https://dreamhack.io request"; sid:12; rev:1;)
```

서버가 https://dreamhack.io 에 요청을 보내는 것을 탐지합니다.

### Rule 13
```
alert https $HOME_NET any -> 54.166.21.139 443 (msg:"https://wiki.vg request"; sid:13; rev:1;)
```

서버가 https://wiki.vg 에 요청을 보내는 것을 탐지합니다.

### Rule 14
```
alert https $HOME_NET any -> 157.230.37.202 443 (msg:"https://felixcloutier.com request"; sid:14; rev:1;)
```

서버가 https://felixcloutier.com 에 요청을 보내는 것을 탐지합니다.

### Rule 15
```
alert https $HOME_NET any -> 104.18.49.127 443 (msg:"https://awesomeopensource.com request"; sid:15; rev:1;)
```

서버가 https://awesomeopensource.com 에 요청을 보내는 것을 탐지합니다.

### Rule 16
```
alert https $HOME_NET any -> 13.225.118.37 443 (msg:"https://acmicpc.net request"; sid:16; rev:1;)
```

서버가 https://acmicpc.net 에 요청을 보내는 것을 탐지합니다.

### Rule 17
```
alert tcp $HOME_NET any <> any any (msg:"Port 10002 TCP connection"; sid:17; rev:1;)
```

10002번 포트에서 발생하는 양방향 TCP 연결을 탐지합니다.

### Rule 18
```
alert tcp $HOME_NET 10001 -> any any (msg:"Port 10001 TCP connection (out)"; sid:18; rev:1;)
```

10001번 포트에서 전송하는 TCP 연결을 탐지합니다.

### Rule 19
```
alert tcp any any -> $HOME_NET 10001 (msg:"Port 10001 TCP connection (in)"; sid:19; rev:1;)
```

10001번 포트로 들어오는 TCP 연결을 탐지합니다.

### Rule 20
```
alert ssh any any -> $HOME_NET 22 (msg:"SSH connection"; sid:20; rev:1;)
```

외부에서 SSH로의 연결을 탐지합니다.