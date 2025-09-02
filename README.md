# osctrl

<p align="center">
  <img alt="osctrl" src="logo.png" width="300" />
  <p align="center">
    Fast and efficient osquery management.
  </p>
  <p align="center">
    <a href="https://github.com/jmpsec/osctrl/blob/master/LICENSE">
      <img alt="Software License" src="https://img.shields.io/badge/license-MIT-green?style=flat-square&fuckgithubcache=1">
    </a>
    <a href="https://github.com/jmpsec/osctrl">
      <img alt="Build Status" src="https://github.com/jmpsec/osctrl/actions/workflows/build_and_test_main_merge.yml/badge.svg?branch=main&fuckgithubcache=1">
    </a>
    <a href="https://goreportcard.com/report/github.com/jmpsec/osctrl">
      <img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/jmpsec/osctrl?style=flat-square&fuckgithubcache=1">
    </a>
  </p>
</p>

## What is osctrl?

**osctrl** is a fast and efficient [osquery](https://osquery.io) management solution, implementing its [remote API](https://osquery.readthedocs.io/en/stable/deployment/remote/) as TLS endpoint.

With **osctrl** you can monitor all your systems running osquery, distribute its configuration fast, collect all the status and result logs and allow you to run on-demand queries.

## Running osctrl with docker for development

You can use docker to run **osctrl** and all the components are defined in the `docker-compose-dev.yml` that ties all the components together, to serve a functional deployment.

Ultimately you can just execute `make docker_dev` and it will automagically build and run **osctrl** locally in docker, for development purposes.

## Documentation

You can find the documentation of the project in [https://osctrl.net](https://osctrl.net)

## Slack

Find us in the #osctrl channel in the official osquery Slack community ([Request an auto-invite!](https://join.slack.com/t/osquery/shared_invite/zt-1wipcuc04-DBXmo51zYJKBu3_EP3xZPA))

## License

**osctrl** is licensed under the [MIT License](https://github.com/jmpsec/osctrl/blob/master/LICENSE).

## Donate

If you like **osctrl** you can send [BTC](bitcoin:bc1qvjep6r6j7a00xyhcgp4g2ea2f4pupaprcvllj5) or [ETH](ethereum:0x99e211251fca06286596498823Fd0a48785B64eB) donations to the following wallets:

<table>
  <tr align="center">
    <td><img alt="bitcoin:bc1qvjep6r6j7a00xyhcgp4g2ea2f4pupaprcvllj5" src="https://osctrl.net/btc.png" width="175" title="bitcoin:bc1qvjep6r6j7a00xyhcgp4g2ea2f4pupaprcvllj5"/></td>
    <td><img alt="ethereum:0x99e211251fca06286596498823Fd0a48785B64eB" src="https://osctrl.net/eth.png" width="175" title="ethereum:0x99e211251fca06286596498823Fd0a48785B64eB"/></td>
  </tr>
  <tr align="center">
    <td><sub>bitcoin:bc1qvjep6r6j7a00xyhcgp4g2ea2f4pupaprcvllj5</sub></td>
    <td><sub>ethereum:0x99e211251fca06286596498823Fd0a48785B64eB</sub></td>
  </tr>
</table>
