import { defineConfig } from "vitepress";
import { withMermaid } from "vitepress-plugin-mermaid";
import footnote from "markdown-it-footnote";
import { inlineSvg } from "./inlineSvg.ts";

export default withMermaid(
  defineConfig({
    srcDir: "./docs",
    lang: "ja-JP",
    title: "作って学ぶTLS 1.3",
    description: "Goでクライアントを実装しながら学ぶ",

    head: [
      ["link", { rel: "icon", href: "/favicon.ico", sizes: "48x48" }],
      ["link", { rel: "icon", href: "/favicon.svg", type: "image/svg+xml" }],
      ["link", { rel: "apple-touch-icon", href: "/apple-touch-icon.png" }],
    ],

    mermaid: {
      flowchart: { wrappingWidth: 400 },
    },

    vite: {
      optimizeDeps: {
        include: ["mermaid"],
      },
    },

    markdown: {
      theme: { light: "light-plus", dark: "material-theme-darker" },
      math: true,
      config: (md) => {
        md.use(footnote);
        md.use(inlineSvg);
      },
    },

    themeConfig: {
      socialLinks: [
        { icon: "github", link: "https://github.com/yishida0/tls13-book" },
      ],

      sidebar: [
        { text: "はじめに", link: "/" },
        { text: "環境構築", link: "/01_overview/setup" },
        {
          text: "第1章 TLS 1.3通信の全体像",
          collapsed: false,
          items: [
            { text: "イントロダクション", link: "/01_overview/intro" },
            { text: "TLS 1.3通信の全体像", link: "/01_overview/overview" },
            { text: "実装の流れ", link: "/01_overview/roadmap" },
            // { text: "RFCの読み方", link: "/01_overview/rfc" },
          ],
        },
        {
          text: "第2章 TLSレコードの構造",
          collapsed: false,
          items: [
            { text: "Recordプロトコル", link: "/02_record/record" },
            { text: "Handshakeプロトコル", link: "/02_record/handshake" },
          ],
        },
        {
          text: "第3章 鍵交換とネゴシエーション",
          collapsed: false,
          items: [
            { text: "ClientHello・ServerHelloの役割", link: "/03_kex/hello" },
            { text: "Extension（拡張）を実装する", link: "/03_kex/ext" },
            { text: "鍵配送問題と鍵交換", link: "/03_kex/dh" },
            { text: "ClientHelloを送る", link: "/03_kex/send" },
            { text: "ServerHelloと共有秘密", link: "/03_kex/sh" },
          ],
        },
        {
          text: "第4章 鍵導出",
          collapsed: false,
          items: [
            { text: "HKDFとKey Schedule", link: "/04_keysched/schedule" },
            { text: "Key Scheduleを実装する", link: "/04_keysched/impl" },
          ],
        },
        {
          text: "第5章 共通鍵暗号・AEAD",
          collapsed: false,
          items: [
            { text: "共通鍵暗号", link: "/05_aead/symmetric" },
            { text: "認証付き暗号", link: "/05_aead/aead" },
            { text: "暗号化されたレコード", link: "/05_aead/record" },
            { text: "レコードの暗号化と復号", link: "/05_aead/protection" },
            {
              text: "暗号化されたレコードからメッセージを取り出す",
              link: "/05_aead/decrypt",
            },
            {
              text: "ハンドシェイクを状態機械にまとめる",
              link: "/05_aead/handshake",
            },
          ],
        },
        {
          text: "第6章 PKI・証明書・デジタル署名",
          collapsed: false,
          items: [
            { text: "なりすましの対策とPKI", link: "/06_pki/pki" },
            { text: "デジタル署名", link: "/06_pki/signature" },
            { text: "X.509証明書", link: "/06_pki/x509" },
            { text: "認証局と証明書チェーン", link: "/06_pki/ca" },
            { text: "TLSにおける証明書検証", link: "/06_pki/chain" },
            { text: "証明書チェーンを実装する", link: "/06_pki/verify" },
            {
              text: "CertificateVerifyの署名検証を実装する",
              link: "/06_pki/certverify",
            },
          ],
        },
        {
          text: "第7章 TLSクライアントの完成",
          collapsed: false,
          items: [
            {
              text: "Finishedを実装する",
              link: "/07_finish/finished",
            },
            {
              text: "アプリケーションデータを送受信する",
              link: "/07_finish/https",
            },
            {
              text: "Alertを実装する",
              link: "/07_finish/alert",
            },
            { text: "公開APIを整える", link: "/07_finish/cleanup" },
          ],
        },
        {
          text: "第8章 おわりに",
          collapsed: false,
          items: [{ text: "次に学ぶこと", link: "/08_next/review" }],
        },
        {
          text: "コラム",
          collapsed: false,
          items: [
            { text: "前方秘匿性", link: "/09_column/forward-secrecy" },
            { text: "擬似乱数生成器", link: "/09_column/prng" },
            {
              text: "Certificate Transparency",
              link: "/09_column/certificate-transparency",
            },
          ],
        },
        {
          text: "付録",
          collapsed: false,
          items: [{ text: "参考文献", link: "/references" }],
        },
      ],

      outline: {
        label: "目次",
        level: [2, 3],
      },

      docFooter: {
        prev: "前のページ",
        next: "次のページ",
      },

      search: {
        provider: "local",
      },
    },
  }),
);
