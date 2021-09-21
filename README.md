# nkn-sdk-rust

[![GitHub license](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/giraffekey/nkn-sdk-rust/blob/master/LICENSE)

Rust implementation of NKN client and wallet SDK. The SDK consists of a
few components:

- [NKN Client](#client): Send and receive data for free between any NKN clients
  regardless their network condition without setting up a server or relying on
  any third party services. Data are end to end encrypted by default. Typically
  you might want to use [multiclient](#multiclient) instead of using client
  directly.

- [NKN MultiClient](#multiclient): Send and receive data using multiple NKN
  clients concurrently to improve reliability and latency. In addition, it
  supports session mode, a reliable streaming protocol similar to TCP based
  on [ncp](https://github.com/giraffekey/ncp-rust).

- [NKN Wallet](#wallet): Wallet SDK for [NKN
  blockchain](https://github.com/nknorg/nkn). It can be used to create wallet,
  transfer token to NKN wallet address, register name, subscribe to topic,
  etc.

Advantages of using NKN client/multiclient for data transmission:

- Network agnostic: Neither sender nor receiver needs to have public IP address
  or port forwarding. NKN clients only establish outbound (websocket)
  connections, so Internet access is all they need. This is ideal for client
  side peer to peer communication.

- Top level security: All data are end to end authenticated and encrypted. No
  one else in the world except sender and receiver can see or modify the content
  of the data. The same public key is used for both routing and encryption,
  eliminating the possibility of man in the middle attack.

- Decent performance: By aggregating multiple overlay paths concurrently,
  multiclient can get ~100ms end to end latency and 10+mbps end to end session
  throughput between international devices.

- Everything is free, open source and decentralized. (If you are curious, node
  relay traffic for clients for free to earn mining rewards in NKN blockchain.)

## Documentation

Not created yet.

## Usage

### Client

### Multiclient

### Session

### Wallet

## Contributing

**Can I submit a bug, suggestion or feature request?**

Yes. Please open an issue for that.

**Can I contribute patches?**

Yes, we appreciate your help! To make contributions, please fork the repo, push
your changes to the forked repo with signed-off commits, and open a pull request
here.

Please sign off your commit. This means adding a line "Signed-off-by: Name
<email>" at the end of each commit, indicating that you wrote the code and have
the right to pass it on as an open source patch. This can be done automatically
by adding -s when committing:

```shell
git commit -s
```

## Community

- [Forum](https://forum.nkn.org/)
- [Discord](https://discord.gg/c7mTynX)
- [Telegram](https://t.me/nknorg)
- [Reddit](https://www.reddit.com/r/nknblockchain/)
- [Twitter](https://twitter.com/NKN_ORG)
