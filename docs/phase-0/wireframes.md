# Console wireframes

Open [console-wireframes.html](console-wireframes.html) in a browser. It is a self-contained local navigation prototype with illustrative values and no external resources. The design banner remains visible on every page.

Screens: overview, alert inbox, alert investigation, host activity, rules/suppressions, scenario replay and system health. Navigation buttons and investigation links work. Management/replay actions are text descriptions, not pretend backend controls.

Desktop and 390-pixel mobile navigation/layout were checked in Chromium using Playwright 1.63.0; no page exceptions or mobile document overflow. Screenshots: [overview](../evidence/wireframe-overview.png), [investigation](../evidence/wireframe-investigation.png). These are wireframes, not released application screenshots.

Reproduce the browser check after installing the locked frontend probe packages into `tmp/phase0`:

```sh
docker run --rm --network none --memory 1g --cpus 2 --shm-size 256m \
  -v "$PWD:/work" -w /work mcr.microsoft.com/playwright:v1.63.0-noble@sha256:eff16c30e6f3f4af0a03fa4b706120d5e9b0891c344a27d64559aff5900a4a27 \
  node tools/compatibility/wireframes.cjs
```

The library version must match the browser image. Phase 1 translates the chosen layout into a React console with API-backed data, authorization and browser behavior tests.
