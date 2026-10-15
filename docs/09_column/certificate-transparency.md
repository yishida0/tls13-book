# コラム: Certificate Transparency

CT（Certificate Transparency：証明書の透明性）は、認証局が発行した証明書を、誰でも見られるログに記録する仕組みです。CTの仕様は、[RFC 6962](https://datatracker.ietf.org/doc/html/rfc6962)と、その改訂版の[RFC 9162](https://datatracker.ietf.org/doc/html/rfc9162)です。

## 認証局の不正な発行に気づけない問題

認証局は、任意のドメインの証明書を発行できます。裏を返せば、証明書が誤って、あるいは不正に発行されてしまうと、攻撃者は、その証明書に書かれたドメインのサーバーになりすませます。PKIの信頼は、認証局が正しく振る舞うという前提の上に成り立っています。

2011年には、認証局が正しく振る舞うという前提が崩れる事件が起きました。攻撃者は、オランダの認証局DigiNotarのサーバーに侵入し、\*.google.comを含む531枚の証明書を不正に発行しました。さらに、不正な証明書を使い、主にイランの利用者に中間者攻撃を仕掛けました。DigiNotarの記録には、\*.google.comの不正な証明書を受け取った端末のIPアドレスが約30万件残っており、うち99%以上がイランのものでした。\*.google.comの不正な証明書が見つかったのは、発行から1か月以上たってからでした[^prins2011]。ChromeなどのブラウザがDigiNotarを信頼しなくなり[^adkins2011]、同社は同じ年の9月に破産しました[^vasco2011]。

問題は、認証局が不正な証明書を発行しても、ドメインの持ち主にも利用者にも、気づく手段がなかったことです。認証局がどんな証明書を発行したかは、外からは見えませんでした。

## CTログで不正な発行を見つける

CTでは、認証局は発行する証明書をすべてCTログに登録します。CTログは、登録の証拠としてSCT（Signed Certificate Timestamp：署名付きタイムスタンプ）を認証局に返し、認証局はSCTを証明書に埋め込みます。

CTは、不正な発行を防ぐのではなく、見つけられるようにする仕組みです。RFC 6962の説明は、次のとおりです。

> The logs do not themselves prevent misissue, but they ensure that interested parties (particularly those named in certificates) can detect such misissuance.
> <br><br>
> 訳）ログそのものは不正な発行を防がないが、利害関係者（とくに証明書に名前が載っている者）が不正な発行を見つけられるようにする。
>
> 引用元: [RFC 6962 §1 Informal Introduction](https://datatracker.ietf.org/doc/html/rfc6962#section-1)

ドメインの持ち主は、[crt.sh](https://crt.sh/)のような検索サービスでCTログを調べ、身に覚えのない証明書がないかを確かめられます。2015年には、Googleが、自社の依頼していないgoogle.comの証明書をCTログの中から見つけました。発行したのは、Symantecの認証局でした[^somogyi2015]。

## ブラウザによるCTの必須化

CTログに登録されていない証明書は、ドメインの持ち主がCTログを調べても見つかりません。不正な発行を見つけるには、すべての証明書をCTログに登録させる必要があります。

Googleは、2015年の不正な発行のあと、Symantecに対して、2016年6月1日以降に発行するすべての証明書をCTに対応させるよう求めました。あわせて、CTに対応していないSymantecの証明書については、Googleの製品で警告が出るなどの問題が起きる可能性があると説明しました[^sleevi2015]。

現在、ChromeとSafariは、SCTのない証明書を受け付けません。Chromeの説明は、次のとおりです。

> If a connection is attempted in Chrome and no CT information is provided, then the certificate will be rejected as untrusted, and the connection will be blocked.
> <br><br>
> 訳）Chromeで接続しようとしたときにCTの情報がなければ、証明書は信頼できないものとして拒否され、接続は遮断される。
>
> 引用元: [Certificate Transparency（Chromium）](https://chromium.googlesource.com/chromium/src/+/main/net/docs/certificate-transparency.md)

Safariも、サーバーの証明書が[AppleのCTのポリシー](https://support.apple.com/en-us/103214)を満たさないと、TLSの接続に失敗します。ブラウザが信頼する認証局のほぼすべては、発行する証明書にSCTを埋め込んでいます。本書のクライアントは、SCTを検証しないので、CTログに登録されていない証明書も受け付けます。

[^prins2011]: J. R. Prins, "DigiNotar Certificate Authority breach: Operation Black Tulip (Interim Report)", Fox-IT, 2011. [Report](https://www.sec.gov/Archives/edgar/data/1044777/000119312511241796/dex992.htm)

[^adkins2011]: H. Adkins, "An update on attempted man-in-the-middle attacks", Google Online Security Blog, 2011. [Blog](https://security.googleblog.com/2011/08/update-on-attempted-man-in-middle.html)

[^vasco2011]: VASCO Data Security, "VASCO reports range of estimated losses related to DigiNotar bankruptcy and related events", Press Release, 2011. [Web](https://onespan.com/about/news/newsvasco-reports-range-estimated-losses-related-diginotar-bankruptcy-and-related-events)

[^somogyi2015]: S. Somogyi, A. Eijdenberg, "Improved Digital Certificate Security", Google Online Security Blog, 2015. [Blog](https://security.googleblog.com/2015/09/improved-digital-certificate-security.html)

[^sleevi2015]: R. Sleevi, "Sustaining Digital Certificate Security", Google Online Security Blog, 2015. [Blog](https://security.googleblog.com/2015/10/sustaining-digital-certificate-security.html)
