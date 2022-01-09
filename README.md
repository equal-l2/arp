arpscan
========

## 前提
- Raw SocketまたはBPFを使用できる、Unixまたはそれに類するOS
- C++17に対応したC++コンパイラ
- GNU make (BSD makeなどは不可)

## 使い方

1. `make` でバイナリ`arpscan`を生成する  
(必要に応じて`CXX`環境変数でコンパイラを指定する)

2. 生成された`arpscan`を実行する  
(全IPに対してARPリクエストを送信するため、大きなサブネットに対して実行すると相応の負担がかかることに注意)

```
    $ arpscan <インタフェース>
```

## 参考資料
ARPのEther Typeに対応する数:  
https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml

Ethernet Frame:  
https://en.wikipedia.org/wiki/Ethernet_frame

BPFの使い方  
https://gist.github.com/XiaoFaye/086cb7b90033809b5fe8e6121b23bf4e

getifaddrsでIPアドレスを取ってくる方法  
https://gist.github.com/qxj/5618237

getifaddrsからMACアドレスを取得する方法  
https://stackoverflow.com/questions/6762766/mac-address-with-getifaddrs

Raw socketではsendtoを使わないとうまく動かない  
https://stackoverflow.com/questions/16710040/arp-request-and-reply-using-c-socket-programming

LinuxのRaw Socketに特定のインタフェースを紐付ける方法(SO_BINDTODEVICE)  
https://stackoverflow.com/questions/3998569/how-to-bind-raw-socket-to-specific-interface

LinuxのRaw Socketに特定のインタフェースを紐づける方法(bind)  
https://plasmixs.github.io/raw-sockets-programming-in-c.html

## 雑記
IPv6が動いてるとうまく行かないことがある？(ipv6.disable_ipv6=1で快適に)  

macOS、FreeBSD、DragonFly BSD、OpenBSD、Linuxで動作  
NetBSDはなんか上手くいかない  
//Solarisはbindでしくじる 対応中止  
