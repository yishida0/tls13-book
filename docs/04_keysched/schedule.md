# HKDFとKey Schedule

[第3章](/03_kex/hello)では、ClientHelloとServerHelloを交換し、X25519による鍵交換でサーバーと同じ32バイトの共有秘密を計算しました。

第4章では、この共有秘密をもとに、通信の暗号化に使う鍵を導出します。そのために使うのがHKDFとKey Scheduleです。HKDFは鍵素材から新たな鍵素材を導出する関数で、Key ScheduleはTLS 1.3がHKDFをどの順番で使い、どのような鍵を作るかを定めたものです。本章では、これらの仕組みを学び、実装していきます。

## 共有秘密をそのまま鍵にできない理由

鍵交換で得た共有秘密をそのままAESの鍵にすれば、暗号化通信を始められそうに思えます。しかし、共有秘密をそのまま鍵に使うのは適切ではありません。主に次の3つの問題があるためです。

::: danger 問題点1　出力に偏りがある
鍵交換で得られる共有秘密は、楕円曲線上の点の座標など、数学的な計算によって得られる値です。そのため、すべてのビット列が同じ確率で現れるとは限りません。たとえば、X25519の出力は2<sup>255</sup> − 19未満の値を32バイトで表すため、最上位ビットは必ず0になります。暗号アルゴリズムの鍵として適したビット列を得るには、このような偏りを考慮する必要があります。
:::

::: danger 問題点2　鍵長が合わない
共有秘密の長さは鍵交換方式によって決まり、暗号アルゴリズムが必要とする鍵の長さとは一致するとは限りません。たとえば、X25519の出力は32バイトですが、`TLS_AES_128_GCM_SHA256`で使うAESの鍵は16バイトです。別の暗号アルゴリズムでは、さらに異なる長さの鍵が必要になることもあります。共有秘密から、用途に応じた長さの鍵を生成する仕組みが必要です。
:::

::: danger 問題点3　通信で必要な鍵が1つではない
1回の鍵交換で得られる共有秘密は1つですが、TLSでは通信の向きや段階ごとに異なる鍵を使います。たとえば、通信の向きは「クライアントからサーバー」と「サーバーからクライアント」の2つ、段階は「ハンドシェイク」と「アプリケーションデータ」の2つです。この組み合わせだけでも4種類の暗号鍵が必要になります。1つの共有秘密から、それぞれの用途に応じた鍵を安全に作り分けなければなりません。
:::

さらにTLSでは、鍵の導出にハンドシェイクの内容も取り込み、鍵交換だけでなく通信相手と交渉した内容にも結び付けます。このような処理を共有秘密だけで実現することはできません。

## KDF（Key Derivation Function：鍵導出関数）

そこで使うのが、KDF（Key Derivation Function：鍵導出関数）です。KDFは、共有秘密などの鍵素材から、暗号化に使う鍵や、次の鍵導出に使う鍵素材を生成するための関数です。

TLS 1.3では、KDFとしてHKDF（HMAC-based Extract-and-Expand Key Derivation Function）を使います。HKDFを使うことで、1つの共有秘密から、必要な長さの鍵素材を用途ごとに導出できます。

## HKDF（HMAC-based Extract-and-Expand Key Derivation Function）

HKDFは[RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869)で定義された鍵導出関数です。HMACという、ハッシュ関数を利用したメッセージ認証コードの仕組みを土台にしています。

HKDFの処理は、HKDF-ExtractとHKDF-Expandの2段階に分かれます。Extractで入力の偏りをならして擬似乱数鍵を作り、Expandでそこから必要な長さの鍵素材を取り出します。

### HKDF-Extract

HKDF-Extractは、共有秘密などの入力から、暗号学的に扱いやすい擬似乱数鍵（PRK：Pseudorandom Key）を生成する処理です。

鍵交換で得られる共有秘密は、十分に予測しにくい値であっても、ビット列として一様に分布しているとは限りません。HKDF-Extractは、入力に含まれる予測しにくさを、固定長の擬似乱数鍵へとまとめる役割を持ちます。この処理をExtract（抽出）と呼びます。ただし、元の入力にない予測しにくさを新たに生み出すわけではありません。

$$
\mathrm{PRK} = \text{HKDF-Extract}(\mathit{salt}, \mathrm{IKM})
$$

<p class="math-note"><span>salt：省略可能な値</span><span>IKM：鍵の材料（本書では共有秘密など）</span><span>PRK：擬似乱数鍵</span></p>

### HKDF-Expand

HKDF-Expandは、Extractで生成したPRKから、必要な長さの鍵素材を導出する処理です。

`info`には鍵の用途を区別する情報を渡し、`L`には必要なバイト数を指定します。これにより、同じPRKからでも「クライアントの送信用」「サーバーの送信用」といった用途ごとに異なる鍵素材を作れます。必要な長さに展開することから、Expand（展開）と呼ばれます。

$$
\mathrm{OKM} = \text{HKDF-Expand}(\mathrm{PRK}, \mathit{info}, L)
$$

<p class="math-note"><span>info：用途を区別する情報</span><span>L：取り出すバイト数</span><span>OKM：導出した鍵素材</span></p>

## HKDF-Expand-LabelとDerive-Secret

TLS 1.3では、HKDF-ExtractとHKDF-Expandに加えて、TLS 1.3用のHKDF-Expand-LabelとDerive-Secretという関数を使います。これらはHKDF-Expandに渡す情報を、TLS 1.3で定められた形式に整えるための関数です。

[RFC 9846 §7.1](https://datatracker.ietf.org/doc/html/rfc9846#section-7.1)では、次のように定義されています。

> ```c
> HKDF-Expand-Label(Secret, Label, Context, Length) =
>     HKDF-Expand(Secret, HkdfLabel, Length)
>
> Where HkdfLabel is specified as:
>
> struct {
>     uint16 length = Length;
>     opaque label<7..255> = "tls13 " + Label;
>     opaque context<0..255> = Context;
> } HkdfLabel;
>
> Derive-Secret(Secret, Label, Messages) =
>     HKDF-Expand-Label(Secret, Label,
>                       Transcript-Hash(Messages), Hash.length)
> ```
>
> 引用元: [RFC 9846 §7.1 Key Schedule](https://datatracker.ietf.org/doc/html/rfc9846#section-7.1)

HKDF-Expand-Labelは、`Label`の先頭に`tls13 `を付け、`Context`や出力長とともに`HkdfLabel`という構造にまとめてHKDF-Expandへ渡します。これにより、どの用途の鍵素材を導出するのかを区別できます。

Derive-Secretは、その`Context`にハンドシェイクメッセージのハッシュ値（Transcript Hash）を指定する関数です。つまり、鍵素材の導出に、それまでに交換したハンドシェイクメッセージの内容を反映できます。Transcript Hashについては後ほど説明します。

## Key Schedule

Key Schedule（鍵スケジュール）は、HKDF-ExtractやDerive-Secretを、どの順番で、何を材料にして呼び出すかを定めたものです。TLS 1.3では、その流れが1本の導出ツリーとして規定されています。

### 導出ツリーの全体像

RFC 9846では、Key Schedule全体を次の図で示しています。

> ```
>                  0
>                  |
>                  v
>      PSK -->  HKDF-Extract = Early Secret
>                  |
>                  +-----> Derive-Secret(.,
>                  |                     "ext binder" |
>                  |                     "res binder",
>                  |                     "")
>                  |              = binder_key
>                  |
>                  +-----> Derive-Secret(., "c e traffic",
>                  |                     ClientHello)
>                  |              = client_early_traffic_secret
>                  |
>                  +-----> Derive-Secret(., "e exp master",
>                  |                     ClientHello)
>                  |              = early_exporter_secret
>                  v
>             Derive-Secret(., "derived", "")
>                  |
>   asymmetric     v
>    shared --> HKDF-Extract = Handshake Secret
>    secret        |
>                  +-----> Derive-Secret(., "c hs traffic",
>                  |                     ClientHello...ServerHello)
>                  |              = client_handshake_traffic_secret
>                  |
>                  +-----> Derive-Secret(., "s hs traffic",
>                  |                     ClientHello...ServerHello)
>                  |              = server_handshake_traffic_secret
>                  v
>             Derive-Secret(., "derived", "")
>                  |
>                  v
>         0 --> HKDF-Extract = Main Secret
>                  |
>                  +-----> Derive-Secret(., "c ap traffic",
>                  |                     ClientHello...server Finished)
>                  |              = client_application_traffic_secret_0
>                  |
>                  +-----> Derive-Secret(., "s ap traffic",
>                  |                     ClientHello...server Finished)
>                  |              = server_application_traffic_secret_0
>                  |
>                  +-----> Derive-Secret(., "exp master",
>                  |                     ClientHello...server Finished)
>                  |              = exporter_secret
>                  |
>                  +-----> Derive-Secret(., "res master",
>                                        ClientHello...client Finished)
>                                 = resumption_secret
> ```
>
> 引用元: [RFC 9846 §7.1 Key Schedule](https://datatracker.ietf.org/doc/html/rfc9846#section-7.1)

図は上から下へと処理が進みます。各段のHKDF-Extractには、上からの値をsalt、左からの値をIKMとして渡します。右に伸びる枝は、その段の秘密から用途ごとの秘密を導出する処理です。`Derive-Secret(., ...)`の`.`には、枝の分岐元にある秘密が入ります。

本書ではPSKを使わないため、Early Secretから右へ伸びる枝は使いません。必要な経路だけを抜き出すと、図1のようになります。

```mermaid
flowchart TD
    Z1[/"32バイトのゼロ"/] -->|"salt"| X1["HKDF-Extract"]
    Z1 -->|"IKM"| X1
    X1 --> ES[/"Early Secret"/]
    ES --> DD1["Derive-Secret(.,<br/>#quot;derived#quot;, #quot;#quot;)"]
    DD1 --> D1[/"salt"/]
    D1 -->|"salt"| X2["HKDF-Extract"]
    DHE[/"ECDHEの共有秘密"/] -->|"IKM"| X2
    X2 --> HS[/"Handshake Secret"/]
    HS --> DC["Derive-Secret(.,<br/>#quot;c hs traffic#quot;,<br/>ClientHello...ServerHello)"]
    DC --> CHTS[/"client_handshake_<br/>traffic_secret"/]
    HS --> DS["Derive-Secret(.,<br/>#quot;s hs traffic#quot;,<br/>ClientHello...ServerHello)"]
    DS --> SHTS[/"server_handshake_<br/>traffic_secret"/]
    HS --> DD2["Derive-Secret(.,<br/>#quot;derived#quot;, #quot;#quot;)"]
    DD2 --> D2[/"salt"/]
    D2 -->|"salt"| X3["HKDF-Extract"]
    Z2[/"32バイトのゼロ"/] -->|"IKM"| X3
    X3 --> MS[/"Main Secret"/]
    MS --> DCA["Derive-Secret(.,<br/>#quot;c ap traffic#quot;,<br/>ClientHello...server Finished)"]
    DCA --> CATS[/"client_application_<br/>traffic_secret_0"/]
    MS --> DSA["Derive-Secret(.,<br/>#quot;s ap traffic#quot;,<br/>ClientHello...server Finished)"]
    DSA --> SATS[/"server_application_<br/>traffic_secret_0"/]

&#x20;   classDef traffic fill:#fde2b8,stroke:#d08a2c
&#x20;   class CHTS,SHTS,CATS,SATS traffic
```

*本書で使うKey Scheduleの経路*

図1で色を付けた4つが、本書で導出するtraffic secretです。

PSKを使わない場合、最初のHKDF-Extractには`salt`と`IKM`の両方にゼロを渡します。そのため、Early Secretは毎回同じ値になり、次のHandshake Secretを導出するときの`salt`も一定になります。一方、`IKM`には鍵交換で計算した共有秘密を渡すため、Handshake Secretは接続ごとに異なる値になります。

### traffic secret

traffic secretは、通信の暗号化に使う共通鍵やIV（初期化ベクトル）を導出するための秘密の値です。traffic secret自体をそのままAESの鍵として使うわけではありません。

本書では、通信の向きと段階に応じて、表1の4種類のtraffic secretを導出します。

| 秘密 | 用途 |
|---|---|
| `client_handshake_traffic_secret` | ハンドシェイク後半のクライアント→サーバー |
| `server_handshake_traffic_secret` | ハンドシェイク後半のサーバー→クライアント |
| `client_application_traffic_secret_0` | アプリケーションデータのクライアント→サーバー |
| `server_application_traffic_secret_0` | アプリケーションデータのサーバー→クライアント |

*本書で使う4つのtraffic secret*

### Transcript Hash

図の枝には、`Derive-Secret(., "c hs traffic", ClientHello...ServerHello)`のように、ラベルとともにハンドシェイクメッセージの範囲が指定されています。この範囲のメッセージを連結してハッシュ化した値が、Transcript Hashです。

$$
\text{Transcript-Hash} = \text{SHA-256}(\text{ClientHello} \parallel \text{ServerHello} \parallel \cdots)
$$

ハッシュ化する対象には、各ハンドシェイクメッセージの種別や長さを含めますが、TLSレコードのヘッダは含めません。本書で使う`TLS_AES_128_GCM_SHA256`では、ハッシュ関数としてSHA-256を使います。

Transcript Hashを鍵導出に組み込むことで、導出される秘密は共有秘密だけでなく、実際に交換したハンドシェイクメッセージにも結び付きます。途中でメッセージが改ざんされ、クライアントとサーバーの認識する内容が食い違えば、導出する秘密や後続の検証結果も一致しなくなります。この仕組みは、ハンドシェイクの改ざんを検出するうえで重要な役割を果たします。
