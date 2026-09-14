# ObjectIO brand assets

Mark: the Shard Ring — an O built from eight shards, six data (ink/paper) and two parity (amber, at 12 and 6 o'clock). Never rotate it; never recolor the parity pair.

svg/
  objectio-mark.svg, -on-dark.svg, -mono.svg        the mark alone (mono uses currentColor)
  objectio-logo-horizontal*.svg                     primary lockup, type outlined (no font needed)
  objectio-logo-stacked*.svg                        stacked lockup
  favicon.svg / favicon-small.svg                   full mark ≥48 px; simplified solid ring for 16–32 px
  app-icon.svg                                      512 rounded-square icon
  readme-banner.svg                                 1280×320 header
png/                                                rasters of the above (favicon-small-16/32, app-icon-512/1024, readme-banner-1280/2560 …)
favicon.ico                                         16 + 32 + 48
brand-tokens.css / brand-tokens.json                colors and font stacks

Colors: ink #0c121a · graphite #232933 · slate #677284 · mist #ccd1d9 · paper #f5f7f9
        data #249ff3 · data-deep #0077c7 · data-light #a2d4ff · parity #fc9f30
Fonts:  Sora 600 (wordmark, headings) · IBM Plex Sans (body) · IBM Plex Mono (code)

README usage:
  <p align="center"><img src="assets/readme-banner.png" width="100%" alt="ObjectIO"></p>
