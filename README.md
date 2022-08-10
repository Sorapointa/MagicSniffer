# MagicSniffer

> We have posted an article about this on [sdl.moe](https://sdl.moe/): [原神 2.8 KCP 验证密钥交互流程解析与流量解密](https://sdl.moe/post/magic-sniffer/)

As everyone knows, RSA is the most secure way to encrypt data, but RSA could not prevent **MAGIC** from `WindSeedClientNotify`.

MagicSniffer is a amazing tool could help you decrypt GI traffic by **MAGIC** of `WindSeedClientNotify`.

## Usage

1. Install

```shell
npm install
```

2. Edit `config.json`, locate your GI traffic file.

3. Run

```shell
node app.js
```

## Credit

- [Crepe-Inc/Iridium](https://github.com/Crepe-Inc/Iridium)
